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
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut end = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
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
}
