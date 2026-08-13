//! Network classification flags for a source IP and the bitwise radix
//! trie classifier.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::canonical_ip;

/// Network classification flags for a source IP.
///
/// `local_risk_bucket`: 0..255; 255 is the reserved "blocked" bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NetworkFlags {
    pub reserved: bool,
    pub known_hosting: bool,
    pub known_proxy: bool,
    pub tor_exit: bool,
    pub local_risk_bucket: u8,
}

impl NetworkFlags {
    /// True when the source is in the blocked bucket.
    pub fn blocked(self) -> bool {
        self.local_risk_bucket == 255
    }

    /// Fixed-point network risk contribution, matching the PHP built-in
    /// values: 1000 blocked, 950 reserved, 750 known proxy, 650 Tor exit,
    /// 600 known hosting, 0 otherwise. When several flags are set the worst
    /// category wins. The policy's `>= 900` hard deny fires for BLOCKED and
    /// RESERVED sources (both are operator-supplied CIDR rules that must
    /// never appear as legitimate remote sources); known proxies/hosting and
    /// Tor raise the adaptive score without hard-denying. The `>= 900`
    /// hard deny fires for blocked
    /// sources only.
    pub fn network_risk(self) -> u16 {
        if self.blocked() {
            return 1000;
        }
        if self.reserved {
            return 950;
        }
        if self.known_proxy {
            return 750;
        }
        if self.tor_exit {
            return 650;
        }
        if self.known_hosting {
            return 600;
        }
        0
    }
}

/// Classifies a source IP into network flags.
pub trait NetworkClassifier: Send + Sync {
    fn classify(&self, ip: IpAddr) -> NetworkFlags;
}

/// One parsed CIDR entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrEntry {
    pub network: IpAddr,
    pub prefix: u8,
}

impl CidrEntry {
    /// Parses `"203.0.113.0/24"`-style strings. The prefix must be within
    /// the address family width.
    pub fn parse(s: &str) -> Result<CidrEntry, NetworkError> {
        let (addr, prefix_raw) = s
            .split_once('/')
            .ok_or_else(|| NetworkError::Parse(format!("CIDR entry must include a prefix: {s}")))?;
        let network: IpAddr = addr
            .parse()
            .map_err(|_| NetworkError::Parse(format!("invalid CIDR network address: {addr}")))?;
        let prefix: u8 = prefix_raw
            .parse()
            .map_err(|_| NetworkError::Parse(format!("invalid CIDR prefix: {prefix_raw}")))?;
        let max_bits = match network {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        if prefix > max_bits {
            return Err(NetworkError::Parse(format!(
                "CIDR prefix {prefix} exceeds {max_bits} bits for {s}"
            )));
        }
        Ok(CidrEntry { network, prefix })
    }
}

/// Bitwise radix trie over the canonical address bits.
///
/// IPv4 addresses traverse a depth-32 tree, IPv6 a depth-128 tree; the two
/// families live in SEPARATE tries (a `/0` IPv4 entry can never match an
/// IPv6 address, mirroring the legacy family check). The trie is built
/// ONCE in the constructor; `classify` walks at most `prefix depth` nodes
/// (32/128), never scanning the whole entry list.
///
/// Classification preserves the EXACT legacy semantics: the flags of EVERY
/// matching prefix on the path are combined (OR) — a `/0` hosting entry
/// and a `/32` tor entry both apply to the same address.
#[derive(Debug, Default)]
pub struct CidrNetworkClassifier {
    v4: TrieNode,
    v6: TrieNode,
}

#[derive(Debug, Default)]
struct TrieNode {
    flags: Option<NetworkFlags>,
    children: [Option<Box<TrieNode>>; 2],
}

impl CidrNetworkClassifier {
    /// Builds the trie from `(cidr, flags)` pairs (entries may be in any
    /// order; matches are prefix-based, so insertion order never matters).
    pub fn from_entries(entries: Vec<(CidrEntry, NetworkFlags)>) -> CidrNetworkClassifier {
        let mut classifier = CidrNetworkClassifier::default();
        for (entry, flags) in entries {
            match entry.network {
                IpAddr::V4(_) => insert(&mut classifier.v4, entry, flags),
                IpAddr::V6(_) => insert(&mut classifier.v6, entry, flags),
            }
        }
        classifier
    }

    /// Parses one entry per line: `"cidr,flag1,flag2"` — lines starting
    /// with `#` and blank lines are ignored, whitespace is trimmed.
    pub fn from_file(path: &str) -> Result<CidrNetworkClassifier, NetworkError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| NetworkError::Io(format!("cannot read classifier file {path}: {e}")))?;
        let mut entries = Vec::new();
        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(',').map(str::trim);
            let cidr = parts.next().unwrap_or("");
            if cidr.is_empty() {
                continue;
            }
            let entry = CidrEntry::parse(cidr)?;
            let mut flags = NetworkFlags::default();
            for flag in parts {
                if flag.is_empty() {
                    continue;
                }
                match flag {
                    "reserved" => flags.reserved = true,
                    "hosting" => flags.known_hosting = true,
                    "proxy" => flags.known_proxy = true,
                    "tor" => flags.tor_exit = true,
                    "blocked" => flags.local_risk_bucket = 255,
                    other => return Err(NetworkError::UnknownFlag(other.to_string())),
                }
            }
            entries.push((entry, flags));
        }
        Ok(CidrNetworkClassifier::from_entries(entries))
    }
}

/// Inserts one entry into a family trie: `prefix` ADDRESS bits (the family
/// byte is stripped — it selects the trie, it never counts toward the
/// prefix depth) walk the binary tree; the entry's flags land on the node
/// at the prefix depth (duplicate CIDRs COMBINE their flags, exactly like
/// the legacy linear scan).
fn insert(root: &mut TrieNode, entry: CidrEntry, flags: NetworkFlags) {
    let bits = address_bits(entry.network);
    let mut node = root;
    for &bit in bits.iter().take(entry.prefix as usize) {
        let child = &mut node.children[bit as usize];
        if child.is_none() {
            *child = Some(Box::new(TrieNode::default()));
        }
        node = child.as_mut().expect("child set above");
    }
    match &mut node.flags {
        Some(existing) => merge_flags(existing, flags),
        None => node.flags = Some(flags),
    }
}

/// The canonical address bits, MSB first, WITH the family byte stripped.
fn address_bits(ip: IpAddr) -> Vec<u8> {
    let canonical = canonical_ip(ip);
    let mut bits = Vec::with_capacity((canonical.len() - 1) * 8);
    for byte in &canonical[1..] {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    bits
}

impl NetworkClassifier for CidrNetworkClassifier {
    fn classify(&self, ip: IpAddr) -> NetworkFlags {
        let canonical = canonical_ip(ip);
        let family = canonical[0];
        let root = if family == 0x04 { &self.v4 } else { &self.v6 };
        let bits = address_bits(ip);
        let mut flags = NetworkFlags::default();
        let mut node = root;
        for bit in &bits {
            // Combine every matching prefix's flags on the path.
            if let Some(node_flags) = node.flags {
                merge_flags(&mut flags, node_flags);
            }
            match &node.children[*bit as usize] {
                Some(child) => node = child,
                None => break,
            }
        }
        if let Some(node_flags) = node.flags {
            merge_flags(&mut flags, node_flags);
        }
        flags
    }
}

fn merge_flags(target: &mut NetworkFlags, other: NetworkFlags) {
    target.reserved |= other.reserved;
    target.known_hosting |= other.known_hosting;
    target.known_proxy |= other.known_proxy;
    target.tor_exit |= other.tor_exit;
    if other.blocked() {
        target.local_risk_bucket = 255;
    }
}

/// Classifier construction/parsing error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Parse(String),
    #[error("unknown network flag: {0}")]
    UnknownFlag(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cidr: &str) -> CidrEntry {
        CidrEntry::parse(cidr).unwrap()
    }

    #[test]
    fn hosting_tor_blocked_and_unknown() {
        let classifier = CidrNetworkClassifier::from_entries(vec![
            (
                entry("203.0.113.0/24"),
                NetworkFlags {
                    known_hosting: true,
                    ..Default::default()
                },
            ),
            (
                entry("198.51.100.0/24"),
                NetworkFlags {
                    tor_exit: true,
                    ..Default::default()
                },
            ),
            (
                entry("192.0.2.0/24"),
                NetworkFlags {
                    local_risk_bucket: 255,
                    ..Default::default()
                },
            ),
        ]);

        let hosting: IpAddr = "203.0.113.27".parse().unwrap();
        let flags = classifier.classify(hosting);
        assert!(flags.known_hosting);
        assert_eq!(flags.network_risk(), 600);

        let tor: IpAddr = "198.51.100.9".parse().unwrap();
        let flags = classifier.classify(tor);
        assert!(flags.tor_exit);
        assert_eq!(flags.network_risk(), 650);

        let blocked: IpAddr = "192.0.2.5".parse().unwrap();
        let flags = classifier.classify(blocked);
        assert!(flags.blocked());
        assert_eq!(flags.network_risk(), 1000);

        let unknown: IpAddr = "10.0.0.1".parse().unwrap();
        let flags = classifier.classify(unknown);
        assert_eq!(flags, NetworkFlags::default());
        assert_eq!(flags.network_risk(), 0);
    }

    #[test]
    fn proxy_and_reserved_flags() {
        let classifier = CidrNetworkClassifier::from_entries(vec![
            (
                entry("198.18.0.0/15"),
                NetworkFlags {
                    reserved: true,
                    ..Default::default()
                },
            ),
            (
                entry("100.64.0.0/10"),
                NetworkFlags {
                    known_proxy: true,
                    ..Default::default()
                },
            ),
        ]);
        let reserved = classifier.classify("198.18.3.4".parse().unwrap());
        assert!(reserved.reserved);
        assert_eq!(reserved.network_risk(), 950);
        let proxy = classifier.classify("100.64.1.1".parse().unwrap());
        assert!(proxy.known_proxy);
        assert_eq!(proxy.network_risk(), 750);
    }

    #[test]
    fn worst_category_wins_when_flags_combine() {
        // Multiple categories on one source: the worst (highest) value wins
        // and every combination is distinguishable.
        let f = |flags: NetworkFlags| flags.network_risk();
        assert_eq!(
            f(NetworkFlags {
                known_hosting: true,
                tor_exit: true,
                ..Default::default()
            }),
            650,
            "tor outranks hosting"
        );
        assert_eq!(
            f(NetworkFlags {
                known_hosting: true,
                known_proxy: true,
                ..Default::default()
            }),
            750,
            "proxy outranks hosting"
        );
        assert_eq!(
            f(NetworkFlags {
                reserved: true,
                tor_exit: true,
                ..Default::default()
            }),
            950,
            "reserved outranks tor"
        );
        assert_eq!(
            f(NetworkFlags {
                local_risk_bucket: 255,
                known_proxy: true,
                ..Default::default()
            }),
            1000,
            "blocked outranks proxy"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_normalizes() {
        let classifier = CidrNetworkClassifier::from_entries(vec![(
            entry("203.0.113.0/24"),
            NetworkFlags {
                known_hosting: true,
                ..Default::default()
            },
        )]);
        // ::ffff:203.0.113.27 must match the IPv4 /24.
        let mapped: IpAddr = "::ffff:203.0.113.27".parse().unwrap();
        assert!(classifier.classify(mapped).known_hosting);
    }

    #[test]
    fn ipv4_and_ipv6_never_cross_match() {
        let classifier = CidrNetworkClassifier::from_entries(vec![(
            entry("2001:db8::/32"),
            NetworkFlags {
                known_hosting: true,
                ..Default::default()
            },
        )]);
        assert!(
            !classifier
                .classify("203.0.113.1".parse().unwrap())
                .known_hosting
        );
        assert!(
            classifier
                .classify("2001:db8:1234::5".parse().unwrap())
                .known_hosting
        );
    }

    #[test]
    fn prefix_edge_cases() {
        let classifier = CidrNetworkClassifier::from_entries(vec![
            (
                entry("0.0.0.0/0"),
                NetworkFlags {
                    known_hosting: true,
                    ..Default::default()
                },
            ),
            (
                entry("203.0.113.27/32"),
                NetworkFlags {
                    tor_exit: true,
                    ..Default::default()
                },
            ),
        ]);
        let ip: IpAddr = "203.0.113.27".parse().unwrap();
        let flags = classifier.classify(ip);
        assert!(flags.known_hosting); // /0 matches everything
        assert!(flags.tor_exit); // /32 exact match
        assert!(
            !classifier
                .classify("203.0.113.28".parse().unwrap())
                .tor_exit
        );
    }

    #[test]
    fn file_parsing() {
        let path =
            std::env::temp_dir().join(format!("kiwi-risk-classifier-{}.txt", std::process::id()));
        std::fs::write(&path, "# comment\n\n203.0.113.0/24, hosting, proxy\n198.51.100.0/24,tor\n192.0.2.0/24,blocked\n").unwrap();
        let classifier = CidrNetworkClassifier::from_file(path.to_str().unwrap()).unwrap();
        let flags = classifier.classify("203.0.113.7".parse().unwrap());
        assert!(flags.known_hosting && flags.known_proxy);
        assert!(
            classifier
                .classify("198.51.100.1".parse().unwrap())
                .tor_exit
        );
        assert!(classifier.classify("192.0.2.1".parse().unwrap()).blocked());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn duplicate_cidrs_combine_flags() {
        // Legacy linear scan ORs the flags of every matching entry; the
        // trie must do the same when two entries share one prefix.
        let classifier = CidrNetworkClassifier::from_entries(vec![
            (
                entry("203.0.113.0/24"),
                NetworkFlags {
                    known_hosting: true,
                    ..Default::default()
                },
            ),
            (
                entry("203.0.113.0/24"),
                NetworkFlags {
                    tor_exit: true,
                    ..Default::default()
                },
            ),
        ]);
        let flags = classifier.classify("203.0.113.9".parse().unwrap());
        assert!(flags.known_hosting);
        assert!(flags.tor_exit);
    }

    #[test]
    fn file_parsing_errors() {
        let path = std::env::temp_dir().join(format!(
            "kiwi-risk-classifier-bad-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "203.0.113.0/24,weirdflag\n").unwrap();
        let err = CidrNetworkClassifier::from_file(path.to_str().unwrap()).unwrap_err();
        assert_eq!(err, NetworkError::UnknownFlag("weirdflag".into()));
        std::fs::remove_file(&path).ok();

        let err = CidrNetworkClassifier::from_file("/nonexistent/kiwi-risk.txt").unwrap_err();
        assert!(matches!(err, NetworkError::Io(_)));

        let err = CidrEntry::parse("203.0.113.0/33").unwrap_err();
        assert!(matches!(err, NetworkError::Parse(_)));
        let err = CidrEntry::parse("203.0.113.0").unwrap_err();
        assert!(matches!(err, NetworkError::Parse(_)));
    }
}
