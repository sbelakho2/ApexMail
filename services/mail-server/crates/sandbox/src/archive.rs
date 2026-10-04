//! Bounded archive extraction (audit finding: archive inspection previously
//! only ever scored the OUTER container's raw bytes — a payload nested one
//! archive deep was invisible, and `SandboxConfig`'s zip-bomb knobs were
//! dead configuration).
//!
//! ZIP-family containers (zip / docx / xlsx / pptx / jar / apk) are recursed
//! into up to [`SandboxConfig::max_nesting_depth`] levels, honoring
//! [`SandboxConfig::max_archive_entries`] and
//! [`SandboxConfig::max_total_extracted_size`]. Every extracted entry is
//! re-inspected with [`crate::file_inspector::inspect_file`], so macros,
//! executables, polyglots and scripts inside archives are scored on their
//! DECOMPRESSED content. Extraction is pure in-memory — nothing is written
//! to disk, so archive entry paths cannot escape anywhere (no zip-slip).
//!
//! Everything here is bounded and fail-closed: entry count, total
//! decompressed bytes, and nesting depth are hard caps; when a cap fires,
//! the sweep stops and an explicit finding records WHY the contents were
//! only partially inspected. RAR/7z containers are not extracted (no
//! in-crate decompressor) — they keep the existing byte-heuristic checks
//! plus their encryption risk.

use crate::config::SandboxConfig;
use crate::file_inspector::{self, FileInspection, FileType, InspectionFinding};
use std::io::Cursor;
use std::io::Read as _;
use zip::ZipArchive;

/// Outcome of a bounded extraction sweep over one attachment.
#[derive(Debug, Default)]
pub struct ExtractionOutcome {
    /// Findings from inspecting extracted entries (including nested
    /// archives' contents). Descriptions are prefixed with the entry path.
    pub findings: Vec<InspectionFinding>,
    /// Number of entries successfully extracted and inspected.
    pub entries_inspected: usize,
    /// Total decompressed bytes charged against the extraction budget.
    pub extracted_bytes: u64,
    /// Limits that fired during the sweep (each also carries a finding).
    pub limits_hit: Vec<&'static str>,
}

impl ExtractionOutcome {
    /// Sum of risk contributions from all findings (the engine merges this
    /// into the verdict's risk score).
    pub fn risk(&self) -> f64 {
        self.findings.iter().map(|f| f.risk).sum()
    }

    /// Human-readable summary for the verdict's reasons list.
    pub fn summarize(&self) -> Option<String> {
        if self.entries_inspected == 0 && self.limits_hit.is_empty() {
            return None;
        }
        let mut summary = format!(
            "Bounded archive extraction: inspected {} inner entr{} ({} bytes decompressed)",
            self.entries_inspected,
            if self.entries_inspected == 1 {
                "y"
            } else {
                "ies"
            },
            self.extracted_bytes
        );
        if !self.limits_hit.is_empty() {
            summary.push_str(&format!("; limits hit: {}", self.limits_hit.join(", ")));
        }
        Some(summary)
    }
}

/// Budgets consumed across the WHOLE sweep (shared by every nesting level).
#[derive(Debug, Clone, Copy)]
struct SweepBudget {
    remaining_bytes: u64,
    remaining_entries: u32,
}

/// Run a bounded extraction sweep over an attachment and inspect every
/// extracted entry. Only ZIP-family containers (detected by magic bytes)
/// are recursed into; other file types are inspected in place.
pub fn extract_and_inspect(data: &[u8], config: &SandboxConfig) -> ExtractionOutcome {
    let mut outcome = ExtractionOutcome::default();
    if file_inspector::detect_file_type(data) != FileType::Zip {
        return outcome;
    }
    // Whether the static inspector has ALREADY scored THIS container
    // `ARCHIVE_ENCRYPTED` (identical predicate: `check_archive_encryption`
    // calls the same `is_zip_encrypted` the `inspect_file` Zip branch uses).
    // An encrypted container's contents are uninspected BECAUSE it is
    // encrypted — that consequence is already scored at 7.0, so the sweep
    // must not stack a 3.0 `ARCHIVE_ENTRY_UNREADABLE` on the same container
    // (7 + 3 = 10 crossed `reject_threshold` and flipped QUARANTINE →
    // REJECT, breaking the strip-but-never-reject MTA posture).
    let encrypted_already_scored = matches!(
        file_inspector::check_archive_encryption(data, FileType::Zip),
        file_inspector::ArchiveEncryption::FilesEncrypted
    );
    let mut budget = SweepBudget {
        remaining_bytes: config.max_total_extracted_size,
        remaining_entries: config.max_archive_entries,
    };
    sweep_zip(
        data,
        1,
        "",
        config,
        &mut budget,
        &mut outcome,
        encrypted_already_scored,
    );
    outcome
}

/// Inspect one extracted entry's bytes, prefixing finding descriptions with
/// the entry path so operators can locate the offending content. The
/// `analyze_macros` / `analyze_embedded_urls` switches are honored exactly
/// as for the outer container.
fn push_entry_findings(
    outcome: &mut ExtractionOutcome,
    path: &str,
    inspection: &FileInspection,
    config: &SandboxConfig,
) {
    for finding in &inspection.findings {
        if !config.reports_finding(finding.id) {
            continue;
        }
        outcome.findings.push(InspectionFinding {
            id: finding.id,
            description: format!("archive entry '{path}': {}", finding.description),
            risk: finding.risk,
        });
    }
}

/// Recurse into one ZIP container at nesting level `depth` (the original
/// attachment is level 0; its entries are level 1, and so on).
///
/// `budget` is shared by reference across the WHOLE sweep: every entry
/// decompressed at any nesting level charges the same pool (adversarial
/// verification caught the previous by-value pass, which handed each
/// nested archive a fresh copy of the remaining budget — N sibling zips
/// each got (almost) the full entry/byte budget, so a hostile 25 MB
/// container could amplify `max_total_extracted_size` per sibling).
///
/// `encrypted_already_scored` records whether the container whose bytes
/// are being parsed here has already been scored `ARCHIVE_ENCRYPTED` by
/// the static inspector (for depth 1: the attachment itself; for deeper
/// levels: the entry's own `inspect_file` run). Its unreadability to the
/// parser is a CONSEQUENCE of that encryption and must not be scored
/// again — only genuinely opaque/corrupt containers whose encryption did
/// NOT fire earn `ARCHIVE_ENTRY_UNREADABLE`.
fn sweep_zip(
    data: &[u8],
    depth: u32,
    path_prefix: &str,
    config: &SandboxConfig,
    budget: &mut SweepBudget,
    outcome: &mut ExtractionOutcome,
    encrypted_already_scored: bool,
) {
    if depth > config.max_nesting_depth {
        outcome.limits_hit.push("nesting_depth");
        outcome.findings.push(InspectionFinding {
            id: "ARCHIVE_NESTING_EXCEEDED",
            description: format!(
                "archive nesting exceeds the configured maximum depth {} — deeper contents are uninspected",
                config.max_nesting_depth
            ),
            risk: 5.0,
        });
        return;
    }

    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(archive) => archive,
        Err(_) => {
            // The magic bytes looked like a ZIP but the structure does not
            // parse — treat as opaque (fail-closed direction: the outer
            // container's own findings still apply). When the container is
            // ALREADY scored `ARCHIVE_ENCRYPTED` (7.0), its unreadability
            // is a consequence of that encryption — do not stack a 3.0
            // unreadable finding on the same container (10.0 flipped
            // QUARANTINE → REJECT).
            if !encrypted_already_scored {
                outcome.findings.push(InspectionFinding {
                    id: "ARCHIVE_ENTRY_UNREADABLE",
                    description:
                        "archive container could not be parsed — inner contents uninspected".into(),
                    risk: 3.0,
                });
            }
            return;
        }
    };

    for index in 0..archive.len() {
        if budget.remaining_entries == 0 {
            outcome.limits_hit.push("entry_cap");
            outcome.findings.push(InspectionFinding {
                id: "ARCHIVE_ENTRY_CAP",
                description: format!(
                    "archive holds more than the configured maximum of {} entries — remaining entries are uninspected",
                    config.max_archive_entries
                ),
                risk: 4.0,
            });
            return;
        }
        budget.remaining_entries -= 1;

        let file = match archive.by_index(index) {
            Ok(file) => file,
            Err(_) => {
                // zip 2.4 fails `by_index` with "Password required to
                // decrypt file" for an encrypted entry BEFORE the
                // `file.encrypted()` check below can ever run — so when
                // this container is already scored `ARCHIVE_ENCRYPTED`,
                // this error IS the encryption, already scored at 7.0 on
                // the same container. Do not stack the 3.0 unreadable
                // finding per entry on top of it. Only a genuinely corrupt
                // entry in a container whose encryption did NOT fire is
                // scored here.
                if !encrypted_already_scored {
                    outcome.findings.push(InspectionFinding {
                        id: "ARCHIVE_ENTRY_UNREADABLE",
                        description: "archive entry could not be read — contents uninspected"
                            .into(),
                        risk: 3.0,
                    });
                }
                continue;
            }
        };
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        let path = format!("{path_prefix}{name}");

        // Encrypted entries cannot be decompressed for inspection: fail
        // closed with an explicit finding instead of pretending the
        // content was checked.
        if file.encrypted() {
            outcome.findings.push(InspectionFinding {
                id: "ARCHIVE_NESTED_ENCRYPTED",
                description: format!(
                    "archive entry '{path}' is password-protected — contents cannot be inspected"
                ),
                risk: 3.0,
            });
            continue;
        }

        // Bounded decompression: never read more than the remaining byte
        // budget (+1 so overflow is detectable), no matter what the entry
        // header claims. This is the zip-bomb guard.
        if file.size() > budget.remaining_bytes {
            outcome.limits_hit.push("byte_budget");
            outcome.findings.push(InspectionFinding {
                id: "ARCHIVE_BOMB",
                description: format!(
                    "archive entry '{path}' declares {} decompressed bytes, exceeding the remaining extraction budget of {} bytes — contents uninspected",
                    file.size(),
                    budget.remaining_bytes
                ),
                risk: 6.0,
            });
            return;
        }
        let mut reader = file.take(budget.remaining_bytes.saturating_add(1));
        let mut bytes = Vec::new();
        if reader.read_to_end(&mut bytes).is_err() {
            outcome.findings.push(InspectionFinding {
                id: "ARCHIVE_ENTRY_UNREADABLE",
                description: format!(
                    "archive entry '{path}' failed to decompress — contents uninspected"
                ),
                risk: 3.0,
            });
            continue;
        }
        if bytes.len() as u64 > budget.remaining_bytes {
            outcome.limits_hit.push("byte_budget");
            outcome.findings.push(InspectionFinding {
                id: "ARCHIVE_BOMB",
                description: format!(
                    "archive entry '{path}' decompressed past the extraction budget of {} bytes — a decompression-bomb shape; remaining entries are uninspected",
                    budget.remaining_bytes
                ),
                risk: 6.0,
            });
            return;
        }
        budget.remaining_bytes -= bytes.len() as u64;
        outcome.extracted_bytes += bytes.len() as u64;
        outcome.entries_inspected += 1;

        if bytes.len() as u64 > config.max_file_size {
            // An inner entry larger than the attachment limit itself would
            // have been rejected as a top-level attachment — treat it as a
            // high-risk signal instead of re-inspecting it.
            outcome.findings.push(InspectionFinding {
                id: "ARCHIVE_ENTRY_OVERSIZE",
                description: format!(
                    "archive entry '{path}' is {} bytes (limit {}) — suspiciously oversized inner payload",
                    bytes.len(),
                    config.max_file_size
                ),
                risk: 4.0,
            });
            continue;
        }

        // Re-run the full static inspection on the DECOMPRESSED content —
        // this is the detection the outer container's byte scan could not
        // see (macros, executables, polyglots inside the archive).
        let inspection = file_inspector::inspect_file(&bytes, Some(&name));
        push_entry_findings(outcome, &path, &inspection, config);

        // Nested archive: recurse (depth-bounded). The budget is reborrowed
        // so consumption inside the child is charged to the shared pool.
        // If the entry's own inspection scored ITS bytes `ARCHIVE_ENCRYPTED`,
        // the nested sweep must not re-score that container's unreadability.
        if file_inspector::detect_file_type(&bytes) == FileType::Zip {
            let nested_encrypted_scored = inspection
                .findings
                .iter()
                .any(|f| f.id == "ARCHIVE_ENCRYPTED");
            sweep_zip(
                &bytes,
                depth + 1,
                &format!("{path}/"),
                config,
                &mut *budget,
                outcome,
                nested_encrypted_scored,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Build an in-memory ZIP with the given (name, content) entries.
    fn make_zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (name, content) in entries {
            writer
                .start_file(name.to_string(), SimpleFileOptions::default())
                .expect("start file");
            writer.write_all(content).expect("write entry");
        }
        writer.finish().expect("finish zip").into_inner()
    }

    fn finding_ids(outcome: &ExtractionOutcome) -> Vec<&str> {
        outcome.findings.iter().map(|f| f.id).collect()
    }

    fn config_with(fields: &dyn Fn(&mut SandboxConfig)) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        fields(&mut config);
        config
    }

    #[test]
    fn nested_zip_marker_at_depth_two_is_detected() {
        // Fail-first (audit): extraction did not exist — a payload inside a
        // zip inside a zip was scored on the outer container's bytes only.
        // The marker here is a PE executable at nesting level 2; its bytes
        // are invisible in both containers (stored, but one level deep).
        let payload = b"MZ\x90\x00\x03\x00\x00\x00create-remote-thread".to_vec();
        let inner = make_zip(&[("payload.bin", payload)]);
        let outer = make_zip(&[("inner.zip", inner)]);

        let outcome = extract_and_inspect(&outer, &SandboxConfig::default());

        assert!(
            finding_ids(&outcome).contains(&"EXECUTABLE_PE"),
            "depth-2 PE payload must be detected: {:?}",
            outcome.findings
        );
        let pe = outcome
            .findings
            .iter()
            .find(|f| f.id == "EXECUTABLE_PE")
            .expect("PE finding");
        assert!(
            pe.description.contains("inner.zip/payload.bin"),
            "finding must name the entry path: {}",
            pe.description
        );
        assert!(outcome.risk() >= 8.0);
    }

    #[test]
    fn zip_bomb_is_stopped_by_the_byte_budget() {
        // Highly compressible bomb: 10 MiB of zeros deflates to a few KiB.
        // With a 64 KiB extraction budget the sweep must stop and report
        // the bomb instead of decompressing everything.
        let bomb = make_zip(&[("zeros.bin", vec![0u8; 10 * 1024 * 1024])]);
        let config = config_with(&|c| {
            c.max_total_extracted_size = 64 * 1024;
        });

        let outcome = extract_and_inspect(&bomb, &config);

        assert!(
            finding_ids(&outcome).contains(&"ARCHIVE_BOMB"),
            "byte budget must stop the bomb: {:?}",
            outcome.findings
        );
        assert!(outcome.limits_hit.contains(&"byte_budget"));
        assert!(
            outcome.extracted_bytes <= 64 * 1024 + 1,
            "decompressed bytes must stay within the budget, got {}",
            outcome.extracted_bytes
        );
    }

    #[test]
    fn entry_count_cap_fires() {
        let entries: Vec<(String, Vec<u8>)> = (0..8)
            .map(|i| (format!("file{i}.txt"), b"tiny".to_vec()))
            .collect();
        let borrowed: Vec<(&str, Vec<u8>)> = entries
            .iter()
            .map(|(n, c)| (n.as_str(), c.clone()))
            .collect();
        let zip = make_zip(&borrowed);
        let config = config_with(&|c| {
            c.max_archive_entries = 3;
        });

        let outcome = extract_and_inspect(&zip, &config);

        assert_eq!(
            outcome.entries_inspected, 3,
            "extraction must stop at the configured entry cap"
        );
        assert!(
            finding_ids(&outcome).contains(&"ARCHIVE_ENTRY_CAP"),
            "the cap must be reported: {:?}",
            outcome.findings
        );
        assert!(outcome.limits_hit.contains(&"entry_cap"));
    }

    #[test]
    fn nesting_depth_limit_stops_recursion() {
        // Two nested levels with max_nesting_depth = 1: the level-2 payload
        // must NOT be inspected, and the refusal must be explicit.
        let payload = b"MZ\x90\x00\x03\x00\x00\x00deep-payload".to_vec();
        let level2 = make_zip(&[("deep.bin", payload)]);
        let level1 = make_zip(&[("middle.zip", level2)]);
        let config = config_with(&|c| {
            c.max_nesting_depth = 1;
        });

        let outcome = extract_and_inspect(&level1, &config);

        assert!(
            finding_ids(&outcome).contains(&"ARCHIVE_NESTING_EXCEEDED"),
            "depth limit must be reported: {:?}",
            outcome.findings
        );
        assert!(!finding_ids(&outcome).contains(&"EXECUTABLE_PE"));
        assert!(outcome.limits_hit.contains(&"nesting_depth"));
    }

    #[test]
    fn extraction_budget_is_shared_across_sibling_nested_archives() {
        // Fail-first (adversarial verification): `sweep_zip` passed its
        // budget BY VALUE into the recursion, so every nested archive
        // received a fresh COPY of the remaining budget — N sibling zips
        // each got (almost) the full entry budget, defeating the
        // whole-sweep caps the config documents ("across the whole
        // sweep"). The budget must be charged GLOBALLY: entries inspected
        // inside a child count against the shared budget, and the cap must
        // be reported when the second sibling is refused.
        let inner = make_zip(&[
            ("a.txt", b"inner-a".to_vec()),
            ("b.txt", b"inner-b".to_vec()),
            ("c.txt", b"inner-c".to_vec()),
        ]);
        let outer = make_zip(&[("one.zip", inner.clone()), ("two.zip", inner)]);
        let config = config_with(&|c| {
            c.max_archive_entries = 5;
        });

        let outcome = extract_and_inspect(&outer, &config);

        assert_eq!(
            outcome.entries_inspected, 5,
            "shared budget: 2 container entries + 3 contents of the first sibling \
             (per-subtree copies would inspect all 8)"
        );
        assert!(
            finding_ids(&outcome).contains(&"ARCHIVE_ENTRY_CAP"),
            "the second sibling must be refused by the global cap: {:?}",
            outcome.findings
        );
    }

    #[test]
    fn encrypted_container_resisting_parsing_is_not_double_counted() {
        // Fail-first (MTA cross-crate escalation): a container whose bytes
        // are ALREADY scored ARCHIVE_ENCRYPTED (7.0) must not additionally
        // earn ARCHIVE_ENTRY_UNREADABLE (3.0) when its structure resists
        // parsing — the unreadability IS the encryption, already scored.
        // 7 + 3 = 10 crossed reject_threshold and flipped QUARANTINE →
        // REJECT. Fixture: ZIP local header with the encryption flag set
        // (bit 0 of the general-purpose flags at offset 6) and no central
        // directory, so ZipArchive::new fails while is_zip_encrypted fires.
        let mut zip = vec![0x50u8, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
        zip.extend_from_slice(&[0u8; 64]);
        assert!(
            file_inspector::is_zip_encrypted(&zip),
            "test premise: the fixture must be scored encrypted"
        );
        assert_eq!(
            file_inspector::check_archive_encryption(&zip, FileType::Zip),
            file_inspector::ArchiveEncryption::FilesEncrypted,
            "test premise: suppression predicate matches the inspector"
        );

        let outcome = extract_and_inspect(&zip, &SandboxConfig::default());

        assert!(
            !finding_ids(&outcome).contains(&"ARCHIVE_ENTRY_UNREADABLE"),
            "an encrypted container must not be double-scored as unreadable: {:?}",
            outcome.findings
        );
    }

    #[test]
    fn corrupt_non_encrypted_container_still_reports_unreadable() {
        // The other direction: a genuinely opaque/corrupt container whose
        // encryption did NOT fire keeps the explicit 3.0 finding — the
        // suppression is keyed on scored encryption, not on parse failure.
        let mut zip = vec![0x50u8, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00];
        zip.extend_from_slice(&[0u8; 64]);
        assert!(
            !file_inspector::is_zip_encrypted(&zip),
            "test premise: flags clean, not encrypted"
        );

        let outcome = extract_and_inspect(&zip, &SandboxConfig::default());

        assert!(
            finding_ids(&outcome).contains(&"ARCHIVE_ENTRY_UNREADABLE"),
            "a corrupt non-encrypted container must stay explicitly unreadable: {:?}",
            outcome.findings
        );
    }

    /// A structurally VALID zip whose single entry carries the encrypted
    /// general-purpose flag (like a real ZipCrypto/AES archive): the central
    /// directory parses, but zip 2.4 fails `by_index` with "Password
    /// required to decrypt file" before any per-entry encryption check of
    /// ours can run.
    fn make_parseable_encrypted_zip() -> Vec<u8> {
        fn lfh() -> Vec<u8> {
            let mut h = Vec::new();
            h.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // local signature
            h.extend_from_slice(&20u16.to_le_bytes()); // version needed
            h.extend_from_slice(&0x0001u16.to_le_bytes()); // flags: encrypted
            h.extend_from_slice(&0u16.to_le_bytes()); // method: stored
            h.extend_from_slice(&0u16.to_le_bytes()); // mod time
            h.extend_from_slice(&0u16.to_le_bytes()); // mod date
            h.extend_from_slice(&0u32.to_le_bytes()); // crc32
            h.extend_from_slice(&8u32.to_le_bytes()); // compressed size
            h.extend_from_slice(&8u32.to_le_bytes()); // uncompressed size
            h.extend_from_slice(&1u16.to_le_bytes()); // name length
            h.extend_from_slice(&0u16.to_le_bytes()); // extra length
            assert_eq!(h.len(), 30);
            h.extend_from_slice(b"a"); // name
            h.extend_from_slice(b"12345678"); // (fake) encrypted payload
            h
        }
        fn cdfh(offset: u32) -> Vec<u8> {
            let mut h = Vec::new();
            h.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // central signature
            h.extend_from_slice(&20u16.to_le_bytes()); // version made by
            h.extend_from_slice(&20u16.to_le_bytes()); // version needed
            h.extend_from_slice(&0x0001u16.to_le_bytes()); // flags: encrypted
            h.extend_from_slice(&0u16.to_le_bytes()); // method: stored
            h.extend_from_slice(&0u16.to_le_bytes()); // mod time
            h.extend_from_slice(&0u16.to_le_bytes()); // mod date
            h.extend_from_slice(&0u32.to_le_bytes()); // crc32
            h.extend_from_slice(&8u32.to_le_bytes()); // compressed size
            h.extend_from_slice(&8u32.to_le_bytes()); // uncompressed size
            h.extend_from_slice(&1u16.to_le_bytes()); // name length
            h.extend_from_slice(&0u16.to_le_bytes()); // extra length
            h.extend_from_slice(&0u16.to_le_bytes()); // comment length
            h.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            h.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            h.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            h.extend_from_slice(&offset.to_le_bytes()); // local header offset
            assert_eq!(h.len(), 46);
            h.extend_from_slice(b"a"); // name
            h
        }
        let local = lfh();
        let cd_offset = local.len() as u32;
        let cd = cdfh(cd_offset);
        let mut out = local;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // CD disk
        out.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        out.extend_from_slice(&1u16.to_le_bytes()); // entries total
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes()); // CD size
        out.extend_from_slice(&cd_offset.to_le_bytes()); // CD offset
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out
    }

    #[test]
    fn encrypted_entries_in_parseable_container_do_not_stack_unreadable() {
        // Fail-first (second stacking site): zip 2.4 rejects by_index for an
        // encrypted entry with PASSWORD_REQUIRED — previously that emitted a
        // 3.0 ARCHIVE_ENTRY_UNREADABLE per entry on TOP of the container's
        // 7.0 ARCHIVE_ENCRYPTED (again 10.0 → REJECT). The by_index failure
        // is the encryption, already scored.
        let zip = make_parseable_encrypted_zip();
        assert!(
            file_inspector::is_zip_encrypted(&zip),
            "test premise: the container must be scored encrypted"
        );

        let outcome = extract_and_inspect(&zip, &SandboxConfig::default());

        assert!(
            !finding_ids(&outcome).contains(&"ARCHIVE_ENTRY_UNREADABLE"),
            "a PASSWORD_REQUIRED by_index failure must not re-score encryption as unreadable: {:?}",
            outcome.findings
        );
    }

    #[test]
    fn non_zip_input_is_ignored_by_the_sweep() {
        let outcome = extract_and_inspect(b"plain text, no archive", &SandboxConfig::default());
        assert_eq!(outcome.entries_inspected, 0);
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.summarize(), None);
    }
}
