//! Grounded retrieval over the repo's own documentation.
//!
//! The assistant never answers from model memory alone: product questions are
//! grounded in passages retrieved from `ai_docs_chunks` (indexed from the
//! docs/ tree at reindex time) plus the canonical facts block
//! ([`crate::knowledge`]). Retrieval is hybrid lexical — ts_rank full-text
//! fused with trigram similarity — which needs no model runtime; the
//! `embedding` column is provisioned for vector fusion once an embeddings
//! endpoint is configured.

use sqlx::PgPool;
use std::path::{Path, PathBuf};

/// Where the docs tree lives (mounted into the container; repo `docs/`).
pub fn docs_dir() -> PathBuf {
    std::env::var("AI_DOCS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./docs"))
}

/// A retrieved, citable passage.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetrievedChunk {
    pub path: String,
    pub title: String,
    pub snippet: String,
    pub score: f64,
}

/// Version of the indexed corpus — content hash of the docs tree. Changes
/// only when the docs change, which (a) keys cache invalidation and (b) is
/// stamped on every chat row for auditability.
pub fn docs_version(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut files = collect_markdown(dir);
    files.sort();
    for path in files {
        if let Ok(bytes) = std::fs::read(&path) {
            hasher.update(&bytes);
        }
    }
    let hex = format!("{:x}", hasher.finalize());
    hex[..16].to_string()
}

fn collect_markdown(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(p);
            }
        }
    }
    out
}

/// Max chars per chunk — large enough for a section, small enough to pack
/// several passages into the prompt without crowding out the rules.
const CHUNK_CHARS: usize = 1_600;
const CHUNK_OVERLAP: usize = 200;
/// Cap on passages injected into a prompt.
const MAX_PASSAGES: i64 = 4;

fn chunk_text(text: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let bytes = text.len();
    while start < bytes {
        let end = (start + CHUNK_CHARS).min(bytes);
        // Char-boundary-safe trim: never split a UTF-8 sequence.
        let mut trim_end = end;
        while trim_end > start && !text.is_char_boundary(trim_end) {
            trim_end -= 1;
        }
        let slice = &text[start..trim_end];
        // Prefer breaking at a paragraph boundary near the cap.
        let cut = slice
            .rfind("\n\n")
            .filter(|&i| i > CHUNK_CHARS / 2)
            .unwrap_or(slice.len());
        chunks.push(slice[..cut].trim().to_string());
        start += cut.max(CHUNK_CHARS - CHUNK_OVERLAP);
        if start >= bytes {
            break;
        }
        while start < bytes && !text.is_char_boundary(start) {
            start += 1;
        }
    }
    chunks
}

/// Extract a display title from a markdown file: first `# Heading`, else the
/// file name.
fn title_of(content: &str, path: &Path) -> String {
    content
        .lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l.trim_start_matches("# ").trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("document")
                .to_string()
        })
}

/// `docs/foo.fr.md` → `fr`; plain `.md` → `en`.
fn locale_of(path: &Path) -> String {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    stem.rsplit('.')
        .next()
        .filter(|seg| seg.len() == 2 && seg.chars().all(|c| c.is_ascii_lowercase()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "en".to_string())
}

/// Walk `dir`, chunk every markdown file, and (re)build the index for
/// `docs_version(dir)`. Old versions are pruned so the table only ever holds
/// the current corpus. Returns the number of chunks indexed.
pub async fn reindex(pool: &PgPool, dir: &Path) -> Result<usize, String> {
    if !dir.is_dir() {
        return Err(format!("docs dir not found: {}", dir.display()));
    }
    let version = docs_version(dir);
    let files = collect_markdown(dir);
    let mut count = 0usize;

    for path in files {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let title = title_of(&content, &path);
        let rel = path
            .strip_prefix(dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());
        let locale = locale_of(&path);

        for (idx, chunk) in chunk_text(&content).into_iter().enumerate() {
            if chunk.is_empty() {
                continue;
            }
            sqlx::query(
                r#"INSERT INTO ai_docs_chunks
                       (tenant_scope, docs_version, path, title, locale, chunk_index, content)
                   VALUES ('public', $1, $2, $3, $4, $5, $6)
                   ON CONFLICT (tenant_scope, path, chunk_index, docs_version)
                   DO UPDATE SET title = EXCLUDED.title, content = EXCLUDED.content,
                                 locale = EXCLUDED.locale"#,
            )
            .bind(&version)
            .bind(&rel)
            .bind(&title)
            .bind(&locale)
            .bind(idx as i32)
            .bind(&chunk)
            .execute(pool)
            .await
            .map_err(|e| format!("reindex insert {rel}: {e}"))?;
            count += 1;
        }
    }

    sqlx::query("DELETE FROM ai_docs_chunks WHERE docs_version <> $1")
        .bind(&version)
        .execute(pool)
        .await
        .map_err(|e| format!("reindex prune: {e}"))?;

    Ok(count)
}

/// Hybrid lexical search: ts_rank full-text fused with trigram similarity
/// (RRF). Every query is parameterized; the scope is fixed to public docs.
pub async fn search(pool: &PgPool, query: &str, docs_version: &str) -> Vec<RetrievedChunk> {
    let q = query.trim();
    if q.is_empty() {
        return Vec::new();
    }
    type SearchRow = (String, String, String, f32, f32);
    let rows: Result<Vec<SearchRow>, _> = sqlx::query_as(
        r#"
        WITH fts AS (
            SELECT id, ts_rank(content_tsv, plainto_tsquery('english', $1)) AS s
            FROM ai_docs_chunks
            WHERE docs_version = $2 AND tenant_scope = 'public'
              AND content_tsv @@ plainto_tsquery('english', $1)
        ),
        trg AS (
            SELECT id, similarity(content, $1) AS s
            FROM ai_docs_chunks
            WHERE docs_version = $2 AND tenant_scope = 'public'
              AND similarity(content, $1) > 0.25
        )
        SELECT c.path, c.title, c.content,
               COALESCE(f.s, 0)::real, COALESCE(t.s, 0)::real
        FROM ai_docs_chunks c
        LEFT JOIN fts f ON f.id = c.id
        LEFT JOIN trg t ON t.id = c.id
        WHERE c.docs_version = $2 AND c.tenant_scope = 'public'
          AND (f.id IS NOT NULL OR t.id IS NOT NULL)
        ORDER BY (COALESCE(f.s, 0) * 2.0 + COALESCE(t.s, 0)) DESC
        LIMIT $3
        "#,
    )
    .bind(q)
    .bind(docs_version)
    .bind(MAX_PASSAGES)
    .fetch_all(pool)
    .await;

    match rows {
        Ok(rows) => rows
            .into_iter()
            .map(|(path, title, content, fts, trg)| RetrievedChunk {
                path,
                title,
                snippet: truncate_chars(&content, 700),
                score: fts as f64 * 2.0 + trg as f64,
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "docs search failed; answering from canonical facts only");
            Vec::new()
        }
    }
}

/// Current indexed version (empty string when nothing indexed yet).
pub async fn current_version(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT docs_version FROM ai_docs_chunks LIMIT 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn truncate_chars(s: &str, max: usize) -> String {
    // `char_indices` only ever yields char-boundary offsets, so the cut is
    // boundary-safe by construction (the previous manual walk-back loop was
    // provably dead code). The None arm is the already-short passthrough.
    match s.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", &s[..end]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunking_respects_boundaries_and_overlaps() {
        let text = "para one\n\n".to_string() + &"word ".repeat(800);
        let chunks = chunk_text(&text);
        assert!(chunks.len() >= 2, "expected multiple chunks");
        for c in &chunks {
            assert!(c.chars().count() <= CHUNK_CHARS + 1);
        }
    }

    #[test]
    fn titles_and_locales_extract() {
        let dir = std::env::temp_dir(); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        assert_eq!(
            title_of("# Pricing Guide\nbody", &dir.join("pricing.md")),
            "Pricing Guide"
        );
        assert_eq!(title_of("no heading", &dir.join("x.md")), "x");
        assert_eq!(locale_of(Path::new("/d/foo.fr.md")), "fr");
        assert_eq!(locale_of(Path::new("/d/foo.md")), "en");
        assert_eq!(locale_of(Path::new("/d/foo.de.md")), "de");
    }

    #[test]
    fn docs_version_is_stable_and_sensitive() {
        let tmp = std::env::temp_dir().join("ai_docs_version_test"); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("a.md"), "# A\nhello").unwrap();
        let v1 = docs_version(&tmp);
        assert_eq!(v1, docs_version(&tmp), "stable for unchanged tree");
        assert_eq!(v1.len(), 16);
        std::fs::write(tmp.join("sub/b.md"), "# B\nworld").unwrap();
        assert_ne!(v1, docs_version(&tmp), "changes when docs change");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Hostile corpus and query edges ────────────────────────────────────

    #[tokio::test]
    async fn docs_dir_honors_the_env_override() {
        let _serial = crate::test_support::ENV_SERIAL.lock().await;
        let guard = crate::test_support::EnvGuard::with(&[("AI_DOCS_DIR", Some("/tmp/ai-docs-x"))]);
        assert_eq!(docs_dir(), PathBuf::from("/tmp/ai-docs-x"));
        drop(guard);
        // Unset falls back to the repo-relative default.
        let guard = crate::test_support::EnvGuard::with(&[("AI_DOCS_DIR", None)]);
        assert_eq!(docs_dir(), PathBuf::from("./docs"));
        drop(guard);
    }

    #[test]
    fn collect_markdown_skips_missing_dirs_and_foreign_extensions() {
        assert!(collect_markdown(Path::new("/nonexistent/ai-docs")).is_empty());
        let dir = std::env::temp_dir().join(format!("ai-md-{}", uuid::Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("a.md"), b"x").unwrap();
        std::fs::write(dir.join("b.MD"), b"x").unwrap(); // case-sensitive: not markdown
        std::fs::write(dir.join("c.txt"), b"x").unwrap();
        std::fs::write(dir.join("nested").join("d.md"), b"x").unwrap();
        let mut found = collect_markdown(&dir);
        assert_eq!(found.len(), 2, "only lowercase .md recurses: {found:?}");
        found.sort();
        assert!(found[0].ends_with("a.md"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Chunking must never split a UTF-8 sequence and never wedge on
    /// degenerate input: empty text, exact-cap text, and multibyte corpora
    /// whose character boundaries deliberately miss the byte cap.
    #[test]
    fn chunk_text_survives_multibyte_and_degenerate_input() {
        assert!(chunk_text("").is_empty());
        assert_eq!(chunk_text("short doc"), vec!["short doc"]);
        // Exactly the cap: one chunk, no overlap loop.
        let exact = "w".repeat(CHUNK_CHARS);
        assert_eq!(chunk_text(&exact), vec![exact.as_str()]);

        // Emoji are 4 bytes: byte-cap arithmetic lands mid-character.
        let emoji = "\u{1f98a}".repeat(1000); // 4000 bytes
        let chunks = chunk_text(&emoji);
        assert!(!chunks.is_empty());
        for c in &chunks {
            assert!(!c.is_empty());
            // Slicing already proves char-boundary safety (it would panic).
            assert!(c.chars().all(|ch| ch == '\u{1f98a}'));
        }
        // CJK are 3 bytes with no paragraph breaks anywhere.
        let cjk = "\u{6f22}".repeat(2000);
        let chunks = chunk_text(&cjk);
        assert!(chunks.len() >= 2);
        for c in &chunks {
            assert!(c.chars().all(|ch| ch == '\u{6f22}'));
        }

        // A paragraph break sits exactly at the half-cap boundary: the
        // preference filter requires strictly MORE than half, so the break
        // must not be taken (content is not lost by a bad cut).
        let mut text = "p".repeat(CHUNK_CHARS / 2);
        text.push_str("\n\n");
        text.push_str(&"q".repeat(CHUNK_CHARS * 2));
        let chunks = chunk_text(&text);
        assert!(!chunks.is_empty());
        assert!(chunks[0].contains("qq"), "cut must not swallow content");
    }

    /// A paragraph cut SHORTER than the cap makes the next window start at
    /// `CHUNK_CHARS - CHUNK_OVERLAP`, which lands mid-character for 4-byte
    /// emoji (the paragraph break shifts the char alignment): the
    /// start-advance loop must repair it without panicking.
    #[test]
    fn chunk_start_advance_repairs_multibyte_boundaries() {
        let text = "\u{1f98a}".repeat(300) + "\n\n" + &"\u{1f98a}".repeat(1000);
        let chunks = chunk_text(&text);
        assert!(chunks.len() >= 2);
        for c in &chunks {
            assert!(c.chars().all(|ch| ch == '\u{1f98a}'));
            assert!(!c.is_empty());
        }
    }

    /// A broken docs database degrades to "no passages" (the canonical
    /// facts still answer) — search never panics on query failure.
    #[tokio::test]
    async fn search_degrades_to_empty_on_database_failure() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy("postgresql://apexmail:not-a-real-password@127.0.0.1:1/no-such-db")
            .unwrap();
        let hits = search(&pool, "warmup guidance", "someversion").await;
        assert!(hits.is_empty(), "failures must degrade to no passages");
    }

    #[test]
    fn truncate_chars_bounds_length_and_respects_boundaries() {
        assert_eq!(truncate_chars("short", 700), "short");
        let exactly = "x".repeat(700);
        assert_eq!(truncate_chars(&exactly, 700), exactly);
        let long = "y".repeat(701);
        let cut = truncate_chars(&long, 700);
        assert_eq!(cut.chars().count(), 701, "700 kept chars plus the ellipsis");
        assert!(cut.ends_with('\u{2026}'));

        // Multibyte content cuts at a char boundary with no panic.
        let cjk: String = "\u{6f22}".repeat(800);
        let cut = truncate_chars(&cjk, 700);
        assert_eq!(cut.chars().count(), 701);
        assert!(cut.ends_with('\u{2026}'));
    }

    /// Full reindex → current_version → search → tenant-scope → rotation
    /// flow against the canonical database. Serialized by an advisory lock:
    /// reindex prunes every docs_version except its own, so concurrent tests
    /// would delete each other's corpus.
    #[tokio::test]
    async fn reindex_search_and_tenant_scoping_are_version_and_scope_exact() {
        let Some(_lock) = crate::test_support::serial_lock("docs-index-serial").await else {
            return; // no test database configured
        };
        let Some(pool) = crate::test_support::shared_pool().await else {
            return;
        };
        // Own the table for the whole scenario.
        sqlx::query("DELETE FROM ai_docs_chunks")
            .execute(&pool)
            .await
            .unwrap();

        let dir = std::env::temp_dir().join(format!("ai-reindex-{}", uuid::Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join("pricing.md"),
            "# Pricing Guide\n\nWarmup guidance: start with engaged recipients \
             and monitor spam complaints.\n\nPAYG tiers apply per email.\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("guide.fr.md"),
            "# Guide fran\u{e7}ais\n\nConseils de d\u{e9}livrabilit\u{e9} pour les campagnes.\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("sub").join("nested.md"),
            "# Nested\n\nDeep doc content.\n",
        )
        .unwrap();
        std::fs::write(dir.join("only-blank.md"), "\n\n   \n\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "not markdown").unwrap();
        // Invalid UTF-8: the file is skipped, reindex does not fail.
        std::fs::write(dir.join("broken.md"), b"\xff\xfe invalid utf8").unwrap();

        let count = reindex(&pool, &dir).await.unwrap();
        assert_eq!(
            count, 3,
            "blank chunks, .txt and invalid-UTF-8 files are skipped"
        );

        let version = docs_version(&dir);
        assert_eq!(current_version(&pool).await, version);

        // ── search returns scoped, bounded, scored passages ──────────────
        let hits = search(&pool, "warmup guidance", &version).await;
        assert!(!hits.is_empty(), "FTS must match indexed text");
        for hit in &hits {
            assert!(hit.path.starts_with("pricing") || hit.path.starts_with("sub/"));
            assert!(hit.score > 0.0);
            assert!(hit.snippet.chars().count() <= 701);
        }

        // Empty and whitespace-only queries never reach the database.
        assert!(search(&pool, "", &version).await.is_empty());
        assert!(search(&pool, "   ", &version).await.is_empty());

        // A hostile SQL payload is data, not code: plainto_tsquery
        // neutralizes it and the table survives.
        let injection = "'; DROP TABLE ai_docs_chunks; --";
        let _ = search(&pool, injection, &version).await;
        let still_there: i64 = sqlx::query_scalar("SELECT count(*) FROM ai_docs_chunks")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(still_there >= 3, "table must survive a hostile query");

        // Unknown version: nothing to search.
        assert!(search(&pool, "warmup guidance", "0000000000000000")
            .await
            .is_empty());

        // ── tenant scoping: another scope's rows are unreachable ─────────
        sqlx::query(
            "INSERT INTO ai_docs_chunks (tenant_scope, docs_version, path, title, locale, chunk_index, content) \
             VALUES ('tenant-other', $1, 'secret.md', 'Secret', 'en', 0, \
                     'warmup guidance for the other tenant only')",
        )
        .bind(&version)
        .execute(&pool)
        .await
        .unwrap();
        let scoped = search(&pool, "warmup guidance", &version).await;
        assert!(
            !scoped.iter().any(|c| c.path == "secret.md"),
            "search is fixed to the public scope, got {:?}",
            scoped.iter().map(|c| &c.path).collect::<Vec<_>>()
        );

        // ── idempotent reindex: upsert, no duplicates ────────────────────
        let again = reindex(&pool, &dir).await.unwrap();
        assert_eq!(again, count);
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM ai_docs_chunks WHERE docs_version = $1")
                .bind(&version)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            rows,
            count as i64 + 1,
            "the injected foreign-scope row must remain"
        );
        sqlx::query("DELETE FROM ai_docs_chunks WHERE tenant_scope = 'tenant-other'")
            .execute(&pool)
            .await
            .unwrap();

        // ── version rotation: superseded versions are pruned ─────────────
        std::fs::write(
            dir.join("pricing.md"),
            "# Pricing Guide v2\n\nUpdated warmup guidance.\n",
        )
        .unwrap();
        let new_version = docs_version(&dir);
        assert_ne!(version, new_version);
        let new_count = reindex(&pool, &dir).await.unwrap();
        assert_eq!(current_version(&pool).await, new_version);
        let old_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM ai_docs_chunks WHERE docs_version = $1")
                .bind(&version)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(old_rows, 0, "superseded versions are pruned");
        assert_eq!(new_count, 3);

        // A missing directory is an honest error, not an empty success.
        let error = reindex(&pool, Path::new("/nonexistent/ai-docs"))
            .await
            .unwrap_err();
        assert!(error.contains("docs dir not found"));

        sqlx::query("DELETE FROM ai_docs_chunks")
            .execute(&pool)
            .await
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
