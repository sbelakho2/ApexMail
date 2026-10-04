//! Data isolation:connection scoping, RLS, access policies, migration.

use regex::Regex;
use sqlx::PgPool;
use std::sync::LazyLock;
use tracing::{info, warn};

use crate::config::IsolationLevel;
use crate::types::*;

// ── Dangerous Query Patterns ───────────────────────────────

static DANGEROUS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)information_schema",
        r"(?i)pg_catalog",
        r"(?i)SET\s+search_path",
        r"(?i)SET\s+role",
        r"(?i)SET\s+session",
        // set_config( is the functional form of SET and must never appear in
        // tenant-submitted SQL regardless of quoting/whitespace/case.
        r"(?i)set_config\s*\(",
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

static IDENT_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[a-z_][a-z0-9_]{0,62}$").ok());

/// Table references (`FROM x`, `JOIN s.t`, `UPDATE ONLY t`, `INTO "t"`) in
/// the WHITESPACE form, with optional schema qualification and an optional
/// alias candidate (`FROM emails e`, `JOIN contacts AS c`).
///
/// The alias candidate is deliberately unfiltered here — the Rust `regex`
/// crate has no look-arounds, so a clause keyword directly after the table
/// (`FROM emails WHERE …`) is captured as the candidate and rejected in
/// Rust by [`is_alias_keyword`].
///
/// Audit SM5 F9: the alias is what lets the predicate requirement be
/// enforced PER TABLE reference instead of once per query.
static TABLE_REF_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:from|join|update(?:\s+only)?|into)\s+
        (
            (?:"[^"]+"\s*\.\s*)*            # optional quoted schema qualification
            (?:[A-Za-z_][A-Za-z0-9_$]*\s*\.\s*)*  # optional bare schema qualification
            (?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)  # the table name itself
        )
        (?:\s+(?:as\s+)?([A-Za-z_][A-Za-z0-9_$]*))?
        "#,
    )
    .ok()
});

/// Table references in the ZERO-WHITESPACE QUOTED form (audit SM5 F5):
/// PostgreSQL accepts `SELECT * FROM"emails"` — the quote terminates the
/// clause keyword — and the old `\s+`-only pattern never captured the
/// table, so an unscoped tenanted query validated successfully. The
/// capture is everything between the quotes across `"`schema`".`table`"`
/// chains; the existing rsplit/trim post-processing normalizes it.
static TABLE_REF_QUOTED_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:from|join|update(?:\s+only)?|into)"
        ((?:[^"]+"\s*\.\s*)*[^"]+)
        "
        "#,
    )
    .ok()
});

/// Clause keywords that terminate a table reference — an identifier
/// captured right after the table is only an ALIAS when it is not one of
/// these (checked in Rust; the regex crate has no look-arounds).
fn is_alias_keyword(word: &str) -> bool {
    const ALIAS_STOP_KEYWORDS: &[&str] = &[
        "where",
        "on",
        "using",
        "and",
        "or",
        "not",
        "group",
        "order",
        "limit",
        "offset",
        "fetch",
        "union",
        "intersect",
        "except",
        "set",
        "values",
        "returning",
        "when",
        "then",
        "else",
        "end",
        "inner",
        "outer",
        "left",
        "right",
        "full",
        "cross",
        "natural",
        "window",
        "for",
        "select",
        "from",
        "join",
        "as",
        "into",
        "update",
        "delete",
        "insert",
        "only",
        "with",
        "asc",
        "desc",
        "is",
        "null",
        "in",
        "exists",
    ];
    ALIAS_STOP_KEYWORDS.contains(&word.to_ascii_lowercase().as_str())
}

/// Parameterized tenant predicate:`workspace_id = $N`, `workspace_id = ?`,
/// or a current_setting-based RLS binding.
static TENANT_PREDICATE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:workspace_id|organization_id)\s*=\s*(?:\$\d+|\?)
        |
        current_setting\s*\(\s*'app\.(?:current_workspace_id|current_org_id)'
        "#,
    )
    .ok()
});

/// Alias/table-QUALIFIED tenant predicate:`e.workspace_id = $N` — the
/// qualifier (capture 1) is used to enforce the predicate PER TABLE
/// reference (audit SM5 F9): a query joining two tenanted tables must
/// scope BOTH, not just any one of them.
static QUALIFIED_TENANT_PREDICATE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)\b([A-Za-z_][A-Za-z0-9_$]*)\s*\.\s*(?:workspace_id|organization_id)\s*=\s*(?:\$\d+|\?)"#,
    )
    .ok()
});

/// current_setting-based RLS binding (`current_setting('app.current_…')`):
/// applies to the session, so it covers EVERY table reference. The strict
/// `app.*` argument alternation stays: the stripper preserves the content
/// of a literal that immediately follows `current_setting(` (and only
/// that one), so this regex sees the genuine argument while predicates
/// smuggled inside ordinary literals are blanked away (audit SM5 F9
/// repair).
static RLS_BINDING_PREDICATE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?ix)current_setting\s*\(\s*'app\.(?:current_workspace_id|current_org_id)'"#).ok()
});

/// Extract the (lowercased, unquoted) table names referenced by
/// FROM/JOIN/UPDATE/INTO clauses, tolerating schema qualification
/// (`public.emails`) and quoted identifiers (`"Emails"`).
/// Test-only convenience over [`referenced_table_aliases`] (production
/// enforcement needs the aliases for the per-table predicate rule).
#[cfg(test)]
fn referenced_tables(query: &str) -> Vec<String> {
    referenced_table_aliases(query)
        .into_iter()
        .map(|(table, _alias)| table)
        .collect()
}

/// Like [`referenced_tables`], but keeps each reference's optional alias
/// (`FROM emails e` → `("emails", Some("e"))`, `INTO "Emails"` →
/// (`"emails"`, None)) so the predicate requirement can be enforced per
/// table reference (audit SM5 F9).
/// Comma-continued FROM-list entries (audit follow-up found during SM5
/// remediation): PostgreSQL accepts `SELECT * FROM a, b WHERE …`, and a
/// plain FROM/JOIN-keyword scan only captures `a` — the tenanted-table
/// guard never saw `b`, so an unscoped second reference validated
/// successfully. This pattern matches ONE continuation anchored at the
/// comma; [`referenced_table_aliases`] walks it iteratively after each
/// primary FROM match while the text keeps offering `, table` items.
/// Alias capture uses the same shape and the same
/// [`is_alias_keyword`] filter as the primary pattern.
static TABLE_REF_COMMA_CONT_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        \s*,\s*
        (
            (?:"[^"]+"\s*\.\s*)*            # optional quoted schema qualification
            (?:[A-Za-z_][A-Za-z0-9_$]*\s*\.\s*)*  # optional bare schema qualification
            (?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)  # the table name itself
        )
        (?:\s+(?:as\s+)?([A-Za-z_][A-Za-z0-9_$]*))?
        "#,
    )
    .ok()
});

fn referenced_table_aliases(query: &str) -> Vec<(String, Option<String>)> {
    let mut tables = Vec::new();

    if let Some(re) = TABLE_REF_RE.as_ref() {
        for caps in re.captures_iter(query) {
            let Some(m) = caps.get(1) else { continue };
            let reference = m.as_str();
            // Take the last dot-separated segment, strip quoting, lowercase.
            let table = reference
                .rsplit('.')
                .next()
                .unwrap_or(reference)
                .trim()
                .trim_matches('"')
                .trim_matches('"')
                .to_lowercase();
            // The regex crate has no look-arounds: a clause keyword
            // captured as the alias candidate is filtered out here.
            let alias = caps
                .get(2)
                .map(|a| a.as_str().to_string())
                .filter(|a| !is_alias_keyword(a))
                .map(|a| a.to_lowercase());
            if !table.is_empty() {
                tables.push((table, alias));
            }

            // Walk comma-continuations (`FROM a, b, c`) starting at the
            // end of THIS primary match so every entry of the FROM list
            // is extracted. The continuation regex is anchored by
            // requiring the `\s*,\s*` prefix at the scan position; the
            // loop stops at the first non-comma text (WHERE/JOIN/…).
            if let Some(cont_re) = TABLE_REF_COMMA_CONT_RE.as_ref() {
                let mut pos = caps.get(0).map(|c| c.end()).unwrap_or(0);
                while let Some(cont) = cont_re.captures_at(query, pos) {
                    let whole = cont.get(0).unwrap();
                    if whole.start() != pos {
                        break;
                    }
                    let Some(tm) = cont.get(1) else { break };
                    let cont_table = tm
                        .as_str()
                        .rsplit('.')
                        .next()
                        .unwrap_or(tm.as_str())
                        .trim()
                        .trim_matches('"')
                        .trim_matches('"')
                        .to_lowercase();
                    let cont_alias = cont
                        .get(2)
                        .map(|a| a.as_str().to_string())
                        .filter(|a| !is_alias_keyword(a))
                        .map(|a| a.to_lowercase());
                    if cont_table.is_empty() {
                        break;
                    }
                    tables.push((cont_table, cont_alias));
                    pos = whole.end();
                }
            }
        }
    }

    if let Some(re) = TABLE_REF_QUOTED_RE.as_ref() {
        for caps in re.captures_iter(query) {
            let Some(m) = caps.get(1) else { continue };
            let table = m
                .as_str()
                .rsplit('.')
                .next()
                .unwrap_or(m.as_str())
                .trim()
                .trim_matches('"')
                .to_lowercase();
            if !table.is_empty() {
                tables.push((table, None));
            }
        }
    }

    tables
}

/// Strip SQL comments (`-- … EOL` and `/* … */`) while respecting single-quote
/// string literals AND dollar-quoted string literals, so a predicate hidden
/// inside a comment cannot satisfy the tenant-predicate check and comment
/// contents cannot be used for evasion.
///
/// Audit SM5 F5: dollar-quoting (`$$…$$`, `$tag$…$tag$`) previously fell
/// outside the string tracker — a literal like `$q$'$q$` flipped the
/// stripper into single-quote mode at the `'` and swallowed the subsequent
/// REAL `FROM emails` clause (which PostgreSQL then executed live),
/// bypassing the tenanted-table guard. Dollar-quoted spans are now
/// consumed so their contents can neither hide nor masquerade as query
/// structure.
///
/// Audit SM5 F9 repair: the stripped view BLANKS string-literal contents
/// (delimiters kept, content replaced with spaces). A literal is inert
/// text to PostgreSQL — it must never satisfy the tenant-predicate /
/// qualified-predicate / RLS-binding scans, or an attacker rides an
/// ordinary string comparison (`note = 'workspace_id=$1'`) past the guard
/// with no real predicate at all. The ONE literal whose content is
/// structural — the argument of a `current_setting(…)` RLS binding call —
/// is preserved verbatim (see [`ends_with_current_setting_call`]).
fn strip_sql_comments(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let bytes = query.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    // Is the CURRENT single-quoted literal the argument of a
    // current_setting( call? Decided at the opening quote; if true the
    // literal's content is emitted verbatim instead of blanked.
    let mut preserve_literal = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if c == b'\'' {
                // '' is an escaped quote inside the literal
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    if preserve_literal {
                        out.push_str("''");
                    } else {
                        out.push_str("  ");
                    }
                    i += 2;
                    continue;
                }
                in_string = false;
            }
            if preserve_literal {
                out.push(c as char);
            } else {
                // Blank literal content: a space per byte keeps the output
                // aligned without carrying attacker-controlled text into
                // any structure scan.
                out.push(' ');
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => {
                in_string = true;
                preserve_literal = ends_with_current_setting_call(&out);
                out.push('\'');
                i += 1;
            }
            b'$' => {
                // Dollar-quoted string: $$…$$ or $tag$…$tag$. A `$` that
                // does not open a valid dollar quote (e.g. the `$1`
                // parameter placeholders used everywhere in this service)
                // is copied through unchanged. Contents are always blanked
                // (a dollar-quoted span is never a current_setting
                // argument — that form is single-quoted).
                if let Some(open_end) = dollar_tag_end(bytes, i) {
                    let tag = &query[i..open_end];
                    match query[open_end..].find(tag) {
                        Some(rel) => {
                            let end = open_end + rel + tag.len();
                            out.push_str(tag);
                            let content = &query[open_end..open_end + rel];
                            for _ in content.chars() {
                                out.push(' ');
                            }
                            out.push_str(tag);
                            i = end;
                        }
                        None => {
                            // Unterminated dollar quote: the query can never
                            // execute (PostgreSQL rejects it), so stay
                            // CONSERVATIVE and copy the rest verbatim — a
                            // live clause after a malformed literal must
                            // still be visible to the table/predicate scans.
                            out.push_str(&query[i..]);
                            i = bytes.len();
                        }
                    }
                    continue;
                }
                out.push('$');
                i += 1;
            }
            b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                // line comment:skip to end of line
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                out.push('\n');
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                // block comment:skip to closing */
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                out.push(' ');
            }
            _ => {
                // copy one UTF-8 char
                let ch_len = utf8_char_len(bytes, i);
                if let Ok(s) = std::str::from_utf8(&bytes[i..(i + ch_len).min(bytes.len())]) {
                    out.push_str(s);
                    i += ch_len;
                } else {
                    out.push(c as char);
                    i += 1;
                }
            }
        }
    }
    out
}

/// True when the stripped output so far ends with a `current_setting(`
/// call opening (optionally whitespace-separated, case-insensitive) —
/// meaning the literal about to be scanned is that call's string ARGUMENT.
/// The argument is structural (it names the RLS GUC the app sets), so the
/// stripper preserves it verbatim while every other literal is blanked.
fn ends_with_current_setting_call(out: &str) -> bool {
    const OPEN: &str = "current_setting(";
    let trimmed = out.trim_end();
    trimmed.len() >= OPEN.len() && trimmed[trimmed.len() - OPEN.len()..].eq_ignore_ascii_case(OPEN)
}

/// If a dollar-quote tag opens at `bytes[i] == b'$'`, return the byte
/// index just past the opening tag (`$$` or `$tag$`), else `None`.
/// Tags are `$` + zero or more identifier chars + `$`; `$1`-style
/// parameter placeholders contain a digit and are NOT tags.
fn dollar_tag_end(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'_') {
        j += 1;
    }
    if j < bytes.len() && bytes[j] == b'$' {
        Some(j + 1)
    } else {
        None
    }
}

fn utf8_char_len(bytes: &[u8], i: usize) -> usize {
    let b = bytes[i];
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

/// PostgreSQL SQLSTATE for `duplicate_object` (e.g. re-creating a policy).
const DUPLICATE_OBJECT_SQLSTATE: &str = "42710";

// ── Shared→DedicatedSchema capability pre-flight ───────────
//
// The migration copies (then deletes) each table with
// `WHERE workspace_id = $1`, so a shared table that is absent or has no
// `workspace_id` column makes the migration impossible. The canonical
// lineage's `contacts` / `templates` / `campaigns` / `webhooks` are
// TENANT-scoped (`tenant_id`) and never gained a `workspace_id`, and no
// canonical migration creates `public.emails` at all. Inventing a fake
// `workspace_id` column is not an option; instead the migration refuses up
// front and the refusal names every missing object and the migration it
// would need, so an operator can act on it.

/// A table the Shared→DedicatedSchema copy requires in the shared schema,
/// together with the canonical migration file that creates it today (`None`
/// when no canonical migration creates it). No listed migration adds the
/// required `workspace_id` column — that is exactly what the pre-flight
/// reports.
struct TenantTableRequirement {
    table: &'static str,
    created_by: Option<&'static str>,
}

static REQUIRED_TENANT_TABLES: &[TenantTableRequirement] = &[
    TenantTableRequirement {
        table: "campaigns",
        created_by: Some("075_create_missing_tables.sql"),
    },
    TenantTableRequirement {
        table: "contacts",
        created_by: Some("075_create_missing_tables.sql"),
    },
    TenantTableRequirement {
        table: "emails",
        created_by: None,
    },
    TenantTableRequirement {
        table: "templates",
        created_by: Some("075_create_missing_tables.sql"),
    },
    TenantTableRequirement {
        table: "webhooks",
        created_by: Some("075_create_missing_tables.sql"),
    },
];

/// One required tenancy capability that is absent from the shared schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCapabilityGap {
    /// The shared schema that was inspected (production: `public`).
    pub schema: String,
    /// The table missing the capability.
    pub table: &'static str,
    /// `true` when the table itself does not exist; `false` when the table
    /// exists but its `workspace_id` column does not.
    pub table_missing: bool,
    /// Canonical migration file that creates the table today (the table, not
    /// the missing column); `None` for a table the canonical chain never
    /// creates.
    pub created_by: Option<&'static str>,
}

impl MigrationCapabilityGap {
    /// The migration that would have to exist before the copy can touch this
    /// table: a `CREATE TABLE … workspace_id` for an absent table, an
    /// `ALTER TABLE … ADD COLUMN workspace_id` for a non-tenanted one.
    pub fn required_migration(&self) -> String {
        let qualified = format!("{}.{}", self.schema, self.table);
        if self.table_missing {
            format!("CREATE TABLE {qualified} (… workspace_id …)")
        } else {
            format!("ALTER TABLE {qualified} ADD COLUMN workspace_id …")
        }
    }
}

impl std::fmt::Display for MigrationCapabilityGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.table_missing {
            let origin = self
                .created_by
                .map(|migration| format!("last defined by canonical migration {migration}"))
                .unwrap_or_else(|| "no canonical migration creates it".to_string());
            write!(
                f,
                "{}.{}: required table missing; needed migration: {} ({origin})",
                self.schema,
                self.table,
                self.required_migration()
            )
        } else {
            write!(
                f,
                "{}.{}: required column workspace_id missing; needed migration: {} \
                 (table created by canonical migration {})",
                self.schema,
                self.table,
                self.required_migration(),
                self.created_by.unwrap_or("unknown")
            )
        }
    }
}

/// Typed pre-flight refusal for a Shared→DedicatedSchema migration.
///
/// The migration is refused BEFORE any DDL/DML when the shared schema cannot
/// support the copy, so it can never half-apply. Every missing table/column
/// is named together with the migration it would need.
#[derive(Debug)]
pub enum MigrationCapabilityError {
    /// The capability inspection itself failed (catalog/database error);
    /// nothing was attempted.
    Inspection {
        schema: String,
        source: anyhow::Error,
    },
    /// One or more required (table, `workspace_id`) capabilities are absent.
    Missing {
        schema: String,
        gaps: Vec<MigrationCapabilityGap>,
    },
}

impl std::fmt::Display for MigrationCapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inspection { schema, source } => write!(
                f,
                "Shared→DedicatedSchema migration pre-flight could not inspect schema {schema:?}: {source}"
            ),
            Self::Missing { schema, gaps } => {
                writeln!(
                    f,
                    "Shared→DedicatedSchema migration refused: schema {schema:?} is missing {} required \
                     tenancy capability(ies); no data was copied or deleted. Required migrations:",
                    gaps.len()
                )?;
                for gap in gaps {
                    writeln!(f, "  - {gap}")?;
                }
                write!(
                    f,
                    "Apply the listed migrations to the canonical chain, then retry."
                )
            }
        }
    }
}

impl std::error::Error for MigrationCapabilityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspection { source, .. } => Some(source.as_ref()),
            Self::Missing { .. } => None,
        }
    }
}

// ── Data Isolation Service ─────────────────────────────────

pub struct DataIsolationService {
    db: PgPool,
    policies: Vec<DataAccessPolicy>,
    /// Whether the policy set was successfully loaded from the database.
    /// Requests are denied while this is false (fail-closed) — an empty or
    /// failed policy load must never widen access.
    policies_loaded: bool,
}

impl DataIsolationService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            policies: Vec::new(),
            policies_loaded: false,
        }
    }

    /// Load access policies from DB on startup.
    /// Fails loudly:policy load errors are a startup hard error so a
    /// misconfigured database cannot silently disable policy enforcement.
    pub async fn initialize(&mut self) -> anyhow::Result<()> {
        self.policies = self.load_policies().await?;
        self.policies_loaded = true;
        // F63: the access-attempt audit trail (canonical migration 195) is
        // part of this component's persistence contract. A missing relation
        // must fail readiness honestly — every allow/deny decision would
        // otherwise be warn-discarded as an audit-trail gap.
        if !self.audit_schema_ready().await {
            anyhow::bail!(
                "iso_access_attempts relation missing — canonical migration 195 \
                 not applied; access-attempt auditing cannot persist"
            );
        }
        info!(count = self.policies.len(), "Data access policies loaded");
        Ok(())
    }

    /// F63: is the access-attempt audit relation present?
    pub async fn audit_schema_ready(&self) -> bool {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT to_regclass('public.iso_access_attempts')::text",
        )
        .fetch_one(&self.db)
        .await
        .ok()
        .flatten()
        .is_some()
    }

    /// F63: lifecycle cleanup — delete access-attempt audit rows older than
    /// `retention_days` and return how many rows were removed.
    pub async fn cleanup_access_attempts(&self, retention_days: i64) -> Result<u64, sqlx::Error> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days.max(1));
        let result = sqlx::query("DELETE FROM iso_access_attempts WHERE created_at < $1")
            .bind(cutoff)
            .execute(&self.db)
            .await?;
        Ok(result.rows_affected())
    }

    /// Validate a SQL query for safety in a tenant-isolated context.
    pub fn validate_query_access(&self, query: &str, ctx: &IsolationContext) -> bool {
        if !self.policies_loaded {
            warn!(
                user_id = ctx.user_id,
                workspace_id = ctx.workspace_id,
                "Denied query:access policies have not been loaded (fail-closed)"
            );
            return false;
        }

        // Analyze the comment-stripped form so predicates hidden in comments
        // cannot satisfy checks and commented-out clauses cannot evade them.
        let stripped = strip_sql_comments(query);

        // Block dangerous patterns
        for pattern in DANGEROUS_PATTERNS.iter() {
            if pattern.is_match(&stripped) {
                warn!(
                    user_id = ctx.user_id,
                    workspace_id = ctx.workspace_id,
                    "Blocked dangerous query pattern"
                );
                return false;
            }
        }

        // #292:stronger table + predicate checks for SELECT/UPDATE/DELETE with
        // JOIN/CTE-aware parsing. Table extraction tolerates schema
        // qualification (`public.emails`), quoted identifiers, zero
        // whitespace before quoted identifiers (`FROM"emails"`, audit
        // SM5 F5), and arbitrary whitespace/newlines between the clause
        // keyword and the table name.
        let tenanted_tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        let referenced = referenced_table_aliases(&stripped);
        let tenanted_refs: Vec<&(String, Option<String>)> = referenced
            .iter()
            .filter(|(t, _)| tenanted_tables.contains(&t.as_str()))
            .collect();

        if !tenanted_refs.is_empty() {
            // Audit SM5 F9: the predicate requirement is PER TABLE
            // REFERENCE. A single global `workspace_id = $N` used to
            // satisfy the check even when a query joined two tenanted
            // tables and only ONE of them carried the predicate — the
            // other stayed unscoped and could leak cross-workspace rows.
            // Every tenanted reference now needs its own coverage:
            // - an alias-qualified predicate (`e.workspace_id = $1`),
            // - the session-wide RLS binding (`current_setting(…)`), or
            // - when the query touches exactly ONE tenanted reference, a
            //   bare predicate (the ordinary single-table shape, where an
            //   unqualified `workspace_id` is unambiguous).
            let rls_binding = RLS_BINDING_PREDICATE_RE
                .as_ref()
                .map(|re| re.is_match(&stripped))
                .unwrap_or(false);
            let qualified_qualifiers: std::collections::HashSet<String> =
                QUALIFIED_TENANT_PREDICATE_RE
                    .as_ref()
                    .map(|re| {
                        re.captures_iter(&stripped)
                            .filter_map(|caps| caps.get(1))
                            .map(|q| q.as_str().to_lowercase())
                            .collect()
                    })
                    .unwrap_or_default();
            let any_predicate = TENANT_PREDICATE_RE
                .as_ref()
                .map(|re| re.is_match(&stripped))
                .unwrap_or(false);

            for (table, alias) in &tenanted_refs {
                let effective_alias = alias.clone().unwrap_or_else(|| table.clone());
                let covered = rls_binding
                    || qualified_qualifiers.contains(&effective_alias)
                    || (tenanted_refs.len() == 1 && any_predicate);

                if !covered {
                    warn!(
                        user_id = ctx.user_id,
                        workspace_id = ctx.workspace_id,
                        table = %table,
                        alias = %effective_alias,
                        "Blocked query: tenanted table reference without its own parameterized workspace/organization predicate"
                    );
                    return false;
                }
            }
        }

        true
    }

    /// Check if a user has access to a specific resource.
    pub async fn check_resource_access(
        &self,
        ctx: &IsolationContext,
        resource: &str,
        resource_id: &str,
        action: &str,
    ) -> anyhow::Result<bool> {
        // Fail closed:if the policy set never loaded successfully, refuse.
        if !self.policies_loaded {
            warn!(
                user_id = ctx.user_id,
                resource = resource,
                "Denied access:access policies have not been loaded (fail-closed)"
            );
            return Ok(false);
        }

        // Verify workspace ownership
        let owns = self
            .verify_resource_ownership(ctx, resource, resource_id)
            .await?;
        if !owns {
            self.audit_access_attempt(ctx, &ctx.workspace_id, resource, action, false)
                .await;
            return Ok(false);
        }

        // Evaluate policies
        let allowed = self.evaluate_policies(ctx, resource, action);

        if !allowed {
            self.audit_access_attempt(ctx, &ctx.workspace_id, resource, action, false)
                .await;
        }

        Ok(allowed)
    }

    /// Set up Row-Level Security on the given table.
    pub async fn setup_rls(&self, table_name: &str, schema_name: &str) -> anyhow::Result<()> {
        // #293:fail-closed identifier validation for dynamic DDL.
        let table = validate_sql_ident(table_name)?;
        let schema = validate_sql_ident(schema_name)?;
        let table_quoted = quote_sql_ident(&table);
        let schema_quoted = quote_sql_ident(&schema);

        for stmt in rls_statements(&schema_quoted, &table_quoted) {
            match sqlx::query(&stmt).execute(&self.db).await {
                Ok(_) => {}
                // PostgreSQL has no CREATE POLICY IF NOT EXISTS; a repeated
                // setup must stay idempotent (the policies are identical)
                // instead of surfacing a duplicate-object 500 to the caller.
                Err(sqlx::Error::Database(error))
                    if error.code().as_deref() == Some(DUPLICATE_OBJECT_SQLSTATE) => {}
                Err(error) => return Err(error.into()),
            }
        }

        info!(table = table_name, schema = schema_name, "RLS configured");
        Ok(())
    }

    /// Pre-flight capability check for a Shared→DedicatedSchema migration.
    ///
    /// The migration copies (then deletes) every required table with
    /// `WHERE workspace_id = $1`; a table that is absent or has no
    /// `workspace_id` column makes the copy impossible. This inspects the
    /// shared schema up front and returns a typed error naming EVERY missing
    /// table/column and the migration it would need, so the refusal is
    /// diagnosable and the caller fails before any DDL/DML — the migration
    /// can never half-apply.
    pub async fn check_migration_capability(
        &self,
        shared_schema: &str,
    ) -> Result<(), MigrationCapabilityError> {
        let schema = validate_sql_ident(shared_schema).map_err(|error| {
            MigrationCapabilityError::Inspection {
                schema: shared_schema.to_string(),
                source: error,
            }
        })?;
        let required: Vec<&str> = REQUIRED_TENANT_TABLES.iter().map(|r| r.table).collect();

        let existing_tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = $1 AND table_type = 'BASE TABLE' AND table_name = ANY($2)",
        )
        .bind(&schema)
        .bind(&required)
        .fetch_all(&self.db)
        .await
        .map_err(|error| MigrationCapabilityError::Inspection {
            schema: schema.clone(),
            source: error.into(),
        })?;

        let tenanted_tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name FROM information_schema.columns \
             WHERE table_schema = $1 AND column_name = 'workspace_id' AND table_name = ANY($2)",
        )
        .bind(&schema)
        .bind(&required)
        .fetch_all(&self.db)
        .await
        .map_err(|error| MigrationCapabilityError::Inspection {
            schema: schema.clone(),
            source: error.into(),
        })?;

        let mut gaps = Vec::new();
        for requirement in REQUIRED_TENANT_TABLES {
            if !existing_tables.iter().any(|t| t == requirement.table) {
                gaps.push(MigrationCapabilityGap {
                    schema: schema.clone(),
                    table: requirement.table,
                    table_missing: true,
                    created_by: None,
                });
            } else if !tenanted_tables.iter().any(|t| t == requirement.table) {
                gaps.push(MigrationCapabilityGap {
                    schema: schema.clone(),
                    table: requirement.table,
                    table_missing: false,
                    created_by: requirement.created_by,
                });
            }
        }

        if gaps.is_empty() {
            Ok(())
        } else {
            Err(MigrationCapabilityError::Missing { schema, gaps })
        }
    }

    /// Migrate a workspace between isolation levels.
    pub async fn migrate_isolation_level(
        &self,
        workspace_id: &str,
        current_level: &IsolationLevel,
        target_level: &IsolationLevel,
    ) -> anyhow::Result<()> {
        self.migrate_isolation_level_in_schema(workspace_id, current_level, target_level, "public")
            .await
    }

    /// [`Self::migrate_isolation_level`] with an explicit shared source
    /// schema. Production always passes `public`; the parameter exists for
    /// deployments whose shared tables live in another schema, and lets
    /// tests drive the real copy/delete path against a capable schema.
    pub async fn migrate_isolation_level_in_schema(
        &self,
        workspace_id: &str,
        current_level: &IsolationLevel,
        target_level: &IsolationLevel,
        shared_schema: &str,
    ) -> anyhow::Result<()> {
        info!(
            workspace_id = workspace_id,
            from = %current_level,
            to = %target_level,
            "Starting isolation migration"
        );

        // Pre-flight BEFORE the transaction: a Shared→DedicatedSchema
        // migration that cannot run must refuse with every missing
        // table/column named and must write nothing at all.
        if matches!(
            (current_level, target_level),
            (IsolationLevel::Shared, IsolationLevel::DedicatedSchema)
        ) {
            self.check_migration_capability(shared_schema).await?;
        }

        let mut tx = self.db.begin().await?;

        match (current_level, target_level) {
            (IsolationLevel::Shared, IsolationLevel::DedicatedSchema) => {
                self.migrate_to_schema(workspace_id, shared_schema, &mut tx)
                    .await?;
            }
            (IsolationLevel::DedicatedSchema, IsolationLevel::Shared) => {
                self.migrate_from_schema(workspace_id, shared_schema, &mut tx)
                    .await?;
            }
            _ => {
                anyhow::bail!(
                    "Unsupported migration path: {} -> {}",
                    current_level,
                    target_level
                );
            }
        }

        // Update isolation config
        sqlx::query(
            "UPDATE iso_isolation_configs SET current_level=$1, migration_status='completed', updated_at=NOW()
             WHERE workspace_id=$2"
        )
            .bind(target_level.to_string()).bind(workspace_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        info!(workspace_id = workspace_id, "Isolation migration completed");
        Ok(())
    }

    // ── Private ────────────────────────────────────────────

    async fn load_policies(&self) -> anyhow::Result<Vec<DataAccessPolicy>> {
        let rows: Vec<(
            String,
            String,
            String,
            serde_json::Value,
            serde_json::Value,
            String,
        )> = sqlx::query_as(
            "SELECT id, name, resource, conditions, actions, effect FROM iso_access_policies",
        )
        .fetch_all(&self.db)
        .await?;

        let mut policies = Vec::with_capacity(rows.len());
        for (id, name, resource, conditions, actions, effect) in rows {
            policies.push(DataAccessPolicy {
                id,
                name,
                resource,
                conditions: serde_json::from_value(conditions).unwrap_or_default(),
                actions: serde_json::from_value(actions).unwrap_or_default(),
                effect: PolicyEffect::parse(&effect).unwrap_or(PolicyEffect::Deny),
            });
        }
        Ok(policies)
    }

    async fn verify_resource_ownership(
        &self,
        ctx: &IsolationContext,
        resource: &str,
        resource_id: &str,
    ) -> anyhow::Result<bool> {
        let table = resource_to_table(resource);
        let safe = validate_sql_ident(&table)?;
        let safe_quoted = quote_sql_ident(&safe);

        let row: Option<(String,)> = sqlx::query_as(&format!(
            "SELECT workspace_id FROM {} WHERE id = $1",
            safe_quoted
        ))
        .bind(resource_id)
        .fetch_optional(&self.db)
        .await?;

        match row {
            Some((ws_id,)) => Ok(ws_id == ctx.workspace_id),
            None => Ok(false),
        }
    }

    fn evaluate_policies(&self, ctx: &IsolationContext, resource: &str, action: &str) -> bool {
        let matching: Vec<&DataAccessPolicy> = self
            .policies
            .iter()
            .filter(|p| p.resource == resource && p.actions.iter().any(|a| a == action))
            .collect();

        if matching.is_empty() {
            // Default allow if no policies defined for this resource
            return true;
        }

        // Check for deny first
        for policy in &matching {
            if policy.effect == PolicyEffect::Deny
                && self.evaluate_conditions(ctx, &policy.conditions)
            {
                return false;
            }
        }

        // Check for allow
        for policy in &matching {
            if policy.effect == PolicyEffect::Allow
                && self.evaluate_conditions(ctx, &policy.conditions)
            {
                return true;
            }
        }

        false // default deny when explicit policies exist
    }

    fn evaluate_conditions(&self, ctx: &IsolationContext, conditions: &[PolicyCondition]) -> bool {
        conditions.iter().all(|c| {
            let ctx_val = get_context_value(ctx, &c.field);
            match c.operator {
                ConditionOperator::Equals => ctx_val.as_deref() == c.value.as_str(),
                ConditionOperator::NotEquals => ctx_val.as_deref() != c.value.as_str(),
                ConditionOperator::In => {
                    if let Some(arr) = c.value.as_array() {
                        let v = ctx_val.as_deref().unwrap_or("");
                        arr.iter().any(|item| item.as_str() == Some(v))
                    } else {
                        false
                    }
                }
                ConditionOperator::NotIn => {
                    if let Some(arr) = c.value.as_array() {
                        let v = ctx_val.as_deref().unwrap_or("");
                        !arr.iter().any(|item| item.as_str() == Some(v))
                    } else {
                        true
                    }
                }
                ConditionOperator::Contains => ctx_val
                    .as_deref()
                    .map(|v| v.contains(c.value.as_str().unwrap_or("")))
                    .unwrap_or(false),
                ConditionOperator::StartsWith => ctx_val
                    .as_deref()
                    .map(|v| v.starts_with(c.value.as_str().unwrap_or("")))
                    .unwrap_or(false),
            }
        })
    }

    /// Record one access decision in the canonical audit trail
    /// (iso_access_attempts, migration 195). Public so the persistence
    /// contract is exercisable by canonical create/read/restart tests —
    /// the finding's required schema coverage.
    pub async fn audit_access_attempt(
        &self,
        ctx: &IsolationContext,
        target_workspace_id: &str,
        resource: &str,
        action: &str,
        allowed: bool,
    ) {
        if let Err(e) = sqlx::query(
            "INSERT INTO iso_access_attempts (id, organization_id, workspace_id, actor_id, target_workspace_id,
             resource, action, allowed, context, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())"
        )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&ctx.organization_id).bind(&ctx.workspace_id)
            .bind(&ctx.user_id).bind(target_workspace_id)
            .bind(resource).bind(action).bind(allowed)
            .bind(serde_json::json!({"isolation_level": ctx.isolation_level.to_string()}))
            .execute(&self.db)
            .await
        {
            tracing::error!(
                error = %e,
                actor = %ctx.user_id,
                target = %target_workspace_id,
                allowed = allowed,
                "SECURITY: Failed to record access attempt — audit trail gap"
            );
        }
    }

    async fn migrate_to_schema(
        &self,
        workspace_id: &str,
        shared_schema: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        let schema = format!("ws_{}", sanitize_sql_ident(workspace_id));
        let schema_safe = validate_sql_ident(&schema)?;
        let schema_quoted = quote_sql_ident(&schema_safe);
        let source_safe = validate_sql_ident(shared_schema)?;
        let source_quoted = quote_sql_ident(&source_safe);
        sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {}", schema_quoted))
            .execute(&mut **tx)
            .await?;

        let tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        for table in tables {
            let table_quoted = quote_sql_ident(table);
            // Create table in new schema, cloning the shared table's shape.
            sqlx::query(&format!(
                "CREATE TABLE IF NOT EXISTS {}.{} (LIKE {}.{} INCLUDING ALL)",
                schema_quoted, table_quoted, source_quoted, table_quoted
            ))
            .execute(&mut **tx)
            .await?;

            // Copy data
            sqlx::query(&format!(
                "INSERT INTO {}.{} SELECT * FROM {}.{} WHERE workspace_id = $1",
                schema_quoted, table_quoted, source_quoted, table_quoted
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;

            // Delete from shared
            sqlx::query(&format!(
                "DELETE FROM {}.{} WHERE workspace_id = $1",
                source_quoted, table_quoted
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;
        }

        // Update workspace schema_name
        sqlx::query("UPDATE iso_workspaces SET schema_name=$1 WHERE id=$2")
            .bind(&schema)
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    async fn migrate_from_schema(
        &self,
        workspace_id: &str,
        shared_schema: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        // Get current schema
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT schema_name FROM iso_workspaces WHERE id=$1")
                .bind(workspace_id)
                .fetch_optional(&mut **tx)
                .await?;

        let schema = match row.and_then(|r| r.0) {
            Some(s) => s,
            None => anyhow::bail!("No schema found for workspace {}", workspace_id),
        };
        let schema_safe = validate_sql_ident(&schema)?;
        let schema_quoted = quote_sql_ident(&schema_safe);
        let destination_safe = validate_sql_ident(shared_schema)?;
        let destination_quoted = quote_sql_ident(&destination_safe);

        let tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        for table in tables {
            sqlx::query(&format!(
                "INSERT INTO {}.{} SELECT * FROM {}.{} WHERE workspace_id = $1",
                destination_quoted,
                quote_sql_ident(table),
                schema_quoted,
                quote_sql_ident(table)
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;
        }

        // Drop the schema
        sqlx::query(&format!("DROP SCHEMA IF EXISTS {} CASCADE", schema_quoted))
            .execute(&mut **tx)
            .await?;

        sqlx::query("UPDATE iso_workspaces SET schema_name=NULL WHERE id=$1")
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }
}

// ── Helpers ────────────────────────────────────────────────

fn sanitize_sql_ident(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(63)
        .collect()
}

fn validate_sql_ident(s: &str) -> anyhow::Result<String> {
    let normalized = s.trim().to_lowercase();
    let is_valid = IDENT_REGEX
        .as_ref()
        .map(|re| re.is_match(&normalized))
        .unwrap_or(false);
    if !is_valid {
        anyhow::bail!("Invalid SQL identifier: {s}");
    }
    Ok(normalized)
}

fn quote_sql_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// The full set of DDL statements to enable workspace-scoped RLS on a table.
///
/// `FORCE ROW LEVEL SECURITY` is issued alongside `ENABLE`:without FORCE the
/// table *owner* bypasses RLS entirely, so any code path connecting as the
/// owning role would silently defeat tenant isolation. Service accounts that
/// legitimately need to bypass RLS (migrations, backfills) must use a distinct
/// role with the BYPASSRLS attribute — never the owning application role.
fn rls_statements(schema_quoted: &str, table_quoted: &str) -> Vec<String> {
    vec![
        format!(
            "ALTER TABLE {}.{} ENABLE ROW LEVEL SECURITY",
            schema_quoted, table_quoted
        ),
        format!(
            "ALTER TABLE {}.{} FORCE ROW LEVEL SECURITY",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_select ON {}.{} FOR SELECT
               USING (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_insert ON {}.{} FOR INSERT
               WITH CHECK (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_update ON {}.{} FOR UPDATE
               USING (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_delete ON {}.{} FOR DELETE
               USING (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
    ]
}

fn resource_to_table(resource: &str) -> String {
    match resource {
        "email" => "emails".into(),
        "contact" => "contacts".into(),
        "template" => "templates".into(),
        "campaign" => "campaigns".into(),
        "webhook" => "webhooks".into(),
        "api_key" => "api_keys".into(),
        // Reject unknown resources instead of blindly pluralising user input
        other => {
            tracing::error!(resource = %other, "Unknown resource type in data isolation — refusing to guess table name");
            "__unknown__".into()
        }
    }
}

fn get_context_value(ctx: &IsolationContext, field: &str) -> Option<String> {
    match field {
        "organization_id" => Some(ctx.organization_id.clone()),
        "workspace_id" => Some(ctx.workspace_id.clone()),
        "user_id" => Some(ctx.user_id.clone()),
        "isolation_level" => Some(ctx.isolation_level.to_string()),
        _ => {
            // Check permissions
            if field == "permissions" {
                Some(ctx.permissions.join(","))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> IsolationContext {
        IsolationContext {
            organization_id: "org1".into(),
            workspace_id: "ws1".into(),
            user_id: "user1".into(),
            isolation_level: IsolationLevel::Shared,
            schema_name: None,
            permissions: vec!["read".into(), "write".into()],
        }
    }

    #[test]
    fn test_validate_query_blocks_information_schema() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SELECT * FROM information_schema.tables", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_pg_catalog() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SELECT * FROM pg_catalog.pg_tables", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_set_search_path() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SET search_path TO public", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_unscoped_select() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        // SELECT on tenanted table without workspace_id filter
        assert!(
            !svc.validate_query_access("SELECT * FROM emails WHERE subject LIKE '%test%'", &ctx)
        );
    }

    #[test]
    fn test_validate_query_allows_scoped_select() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(svc.validate_query_access(
            "SELECT * FROM emails WHERE workspace_id = $1 AND subject LIKE '%test%'",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_allows_non_tenanted() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(svc.validate_query_access("SELECT * FROM iso_organizations WHERE id = $1", &ctx));
    }

    // ── SQL validator bypass regression tests ──

    fn loaded_svc() -> DataIsolationService {
        DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        }
    }

    #[test]
    fn test_validate_query_blocks_schema_qualified_table() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // Schema qualification previously hid the tenanted table name.
        assert!(!svc.validate_query_access(
            "SELECT * FROM public.emails WHERE subject LIKE '%test%'",
            &ctx
        ));
        // …and is fine when properly parameterized.
        assert!(
            svc.validate_query_access("SELECT * FROM public.emails WHERE workspace_id = $1", &ctx)
        );
    }

    #[test]
    fn test_validate_query_blocks_newline_obfuscated_table() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(!svc
            .validate_query_access("SELECT * FROM\n\temails\nWHERE subject LIKE '%test%'", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_predicate_satisfied_by_comment() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // The workspace predicate only exists inside a comment — the real
        // predicate is a literal comparison. Must be blocked.
        assert!(!svc.validate_query_access(
            "SELECT * FROM emails WHERE subject = 'x' /* workspace_id = $1 */",
            &ctx
        ));
        assert!(!svc.validate_query_access(
            "SELECT * FROM emails WHERE subject = 'x' -- workspace_id = $1",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_blocks_set_config() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // set_config() is the functional form of SET and bypassed the
        // `SET search_path` regex.
        assert!(
            !svc.validate_query_access("SELECT set_config('search_path', 'public', false)", &ctx)
        );
        assert!(!svc.validate_query_access("SELECT SET_CONFIG ( 'role', 'admin', true )", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_literal_workspace_predicate() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // A literal (non-parameterized) workspace predicate must not satisfy
        // the tenancy requirement.
        assert!(!svc.validate_query_access("SELECT * FROM emails WHERE workspace_id = 12345", &ctx));
        // `?` placeholder is an accepted parameterized form.
        assert!(svc.validate_query_access("SELECT * FROM emails WHERE workspace_id = ?", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_update_and_join_without_predicate() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("UPDATE emails SET subject = $1 WHERE id = $2", &ctx));
        assert!(!svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON c.id = e.contact_id WHERE c.id = $1",
            &ctx
        ));
    }

    // ── Audit SM5 F9:the predicate requirement is PER TABLE ──────────

    #[test]
    fn test_join_with_one_scoped_table_is_blocked() {
        // THE finding vector: only `contacts` carries the predicate while
        // `emails` is joined unscoped — cross-workspace email rows leak
        // through the join if the join key does not encode tenancy.
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(
            !svc.validate_query_access(
                "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id WHERE c.workspace_id = $1",
                &ctx
            ),
            "a join with only ONE tenanted table scoped must be blocked"
        );
        // Symmetric case: only emails scoped, contacts unscoped.
        assert!(!svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id WHERE e.workspace_id = $1",
            &ctx
        ));
    }

    #[test]
    fn test_join_with_every_table_scoped_is_allowed() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id \
             WHERE c.workspace_id = $1 AND e.workspace_id = $2",
            &ctx
        ));
    }

    #[test]
    fn test_single_table_bare_predicate_still_allowed() {
        // The unqualified single-table shape is unambiguous and stays legal.
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(svc.validate_query_access(
            "SELECT * FROM emails WHERE workspace_id = $1 ORDER BY created_at DESC",
            &ctx
        ));
    }

    #[test]
    fn test_rls_binding_covers_joined_tables() {
        // A session-wide current_setting RLS binding scopes every reference.
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id \
             WHERE current_setting('app.current_workspace_id') IS NOT NULL",
            &ctx
        ));
    }

    // ── Audit SM5 F5:zero-whitespace table refs + dollar-quote desync ─

    #[test]
    fn test_zero_whitespace_quoted_table_ref_is_detected() {
        // `FROM"emails"` is valid PostgreSQL — the quote terminates the
        // keyword. The old `\s+`-only pattern never captured the table, so
        // an UNSCOPED tenanted query validated successfully.
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(
            !svc.validate_query_access("SELECT * FROM\"emails\" WHERE subject LIKE '%x%'", &ctx),
            "zero-whitespace quoted tenanted table must be detected and blocked without a predicate"
        );
        // …and with the predicate it validates as usual.
        assert!(svc.validate_query_access("SELECT * FROM\"emails\" WHERE workspace_id = $1", &ctx));
    }

    #[test]
    fn test_dollar_quote_does_not_desync_the_comment_stripper() {
        // `$q$'$q$` is a COMPLETE dollar-quoted literal containing a quote.
        // The old stripper flipped into single-quote mode at the `'` and
        // swallowed the subsequent REAL `FROM emails`, validating the
        // unscoped query. The stripper must now consume the dollar quote
        // and leave the live clause visible to the guard.
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(
            !svc.validate_query_access(
                "SELECT '$q$'$q$ || id FROM emails WHERE subject LIKE '%x%'",
                &ctx
            ),
            "a dollar-quoted literal must not hide the live FROM clause"
        );
        // The stripper output: the FROM survives; literal contents are
        // blanked (F9 repair) — only delimiters/tags remain.
        let stripped = strip_sql_comments("SELECT '$q$'$q$ FROM emails");
        assert!(stripped.contains("FROM emails"), "got: {stripped}");
        assert!(
            !stripped.contains("'$q$'"),
            "content must be blanked: {stripped}"
        );
    }

    #[test]
    fn test_dollar_quote_contents_are_blanked_not_preserved() {
        // Comment markers inside a dollar-quoted literal are literal
        // content — they must be BLANKED so a predicate hidden inside them
        // cannot satisfy the guard, while a real predicate after the
        // literal survives.
        let stripped =
            strip_sql_comments("SELECT $$-- workspace_id = $1$$ FROM t WHERE workspace_id = $2");
        assert!(
            stripped.contains("workspace_id = $2"),
            "the live predicate must survive: {stripped}"
        );
        assert!(
            !stripped.contains("--") && !stripped.contains("workspace_id = $1"),
            "dollar-quoted content must be blanked: {stripped}"
        );
    }

    #[test]
    fn test_parameter_placeholders_are_not_dollar_quotes() {
        // `$1`-style placeholders must pass through the stripper untouched.
        let stripped = strip_sql_comments("SELECT * FROM t WHERE a = $1 AND b = $2");
        assert_eq!(stripped, "SELECT * FROM t WHERE a = $1 AND b = $2");
    }

    #[test]
    fn test_referenced_table_aliases_extracted() {
        let refs = referenced_table_aliases(
            "SELECT * FROM\npublic.\"Emails\" e JOIN contacts AS c ON true",
        );
        assert!(
            refs.contains(&("emails".to_string(), Some("e".to_string()))),
            "got: {refs:?}"
        );
        assert!(
            refs.contains(&("contacts".to_string(), Some("c".to_string()))),
            "got: {refs:?}"
        );
        // An alias captured directly after the table is kept verbatim.
        let refs = referenced_table_aliases("SELECT * FROM templates t WHERE t.id = $1");
        assert!(
            refs.contains(&("templates".to_string(), Some("t".to_string()))),
            "got: {refs:?}"
        );
        // A clause keyword directly after the table is not an alias.
        let refs = referenced_table_aliases("SELECT * FROM emails WHERE workspace_id = $1");
        assert_eq!(refs, vec![("emails".to_string(), None)], "got: {refs:?}");
    }

    #[test]
    fn test_validate_query_fail_closed_when_policies_not_loaded() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: false,
        };
        let ctx = make_ctx();
        assert!(
            !svc.validate_query_access("SELECT * FROM iso_organizations WHERE id = $1", &ctx),
            "queries must be denied while policies are not loaded (fail-closed)"
        );
    }

    #[test]
    fn test_strip_sql_comments_preserves_strings() {
        // `--` inside a string literal is not a comment: the clause AFTER
        // the literal must survive (had `--` opened a comment, `FROM t`
        // would have been swallowed).
        let stripped = strip_sql_comments("SELECT 'a--b' FROM t");
        assert!(stripped.contains("FROM t"), "got: {}", stripped);
        // F9 repair: literal CONTENT is blanked, so a predicate inside a
        // literal cannot satisfy the guard.
        assert!(!stripped.contains("a--b"), "got: {}", stripped);
        // Block comment removed.
        let stripped = strip_sql_comments("SELECT 1 /* hidden workspace_id = $1 */ FROM t");
        assert!(!stripped.contains("workspace_id"), "got: {}", stripped);
    }

    // ── Audit SM5 F9 repair: literals cannot satisfy predicate scans ──

    #[test]
    fn test_literal_contents_cannot_satisfy_workspace_predicate() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // The ONLY "predicate" lives inside a dead string literal. The
        // old scans matched it and validated an unscoped query.
        assert!(
            !svc.validate_query_access("SELECT * FROM emails WHERE note = 'workspace_id=$1'", &ctx),
            "a predicate smuggled inside a literal must not satisfy the guard"
        );
        // The same shape for the RLS binding form.
        assert!(
            !svc.validate_query_access(
                "SELECT * FROM emails WHERE note = 'current_setting(''app.current_workspace_id'')'",
                &ctx
            ),
            "an RLS binding smuggled inside a literal must not satisfy the guard"
        );
        // …and the genuine predicate next to a literal still validates.
        assert!(svc.validate_query_access(
            "SELECT * FROM emails WHERE note = 'workspace_id=$1' AND workspace_id = $1",
            &ctx
        ));
    }

    #[test]
    fn test_literal_contents_cannot_cover_a_join_alias() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // F9 per-alias coverage defeated by a smuggled QUALIFIED predicate:
        // `emails` looks scoped, but its "predicate" is inert literal text.
        assert!(
            !svc.validate_query_access(
                "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id \
                 WHERE c.workspace_id = $1 AND e.note = 'e.workspace_id=$2'",
                &ctx
            ),
            "a smuggled alias-qualified predicate must not cover the joined table"
        );
        // The genuine form stays allowed.
        assert!(svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id \
             WHERE c.workspace_id = $1 AND e.workspace_id = $2",
            &ctx
        ));
    }

    #[test]
    fn test_current_setting_argument_is_preserved_for_rls_binding() {
        // The one literal whose content is structural: the argument of a
        // current_setting( RLS binding call must survive blanking so the
        // genuine binding keeps covering joined tables.
        let stripped = strip_sql_comments(
            "SELECT * FROM emails WHERE current_setting('app.current_workspace_id') IS NOT NULL",
        );
        assert!(
            stripped.contains("'app.current_workspace_id'"),
            "current_setting argument must be preserved: {stripped}"
        );
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id \
             WHERE current_setting('app.current_workspace_id') IS NOT NULL",
            &ctx
        ));
        // A non-app argument is NOT an RLS binding.
        assert!(
            !svc.validate_query_access(
                "SELECT * FROM contacts c JOIN emails e ON e.contact_id = c.id \
                 WHERE current_setting('statement_timeout') IS NOT NULL",
                &ctx
            ),
            "an unrelated current_setting argument must not act as an RLS binding"
        );
    }

    #[test]
    fn test_referenced_tables_handles_qualification_and_whitespace() {
        let tables = referenced_tables("SELECT * FROM\npublic.\"Emails\" e JOIN contacts ON true");
        assert!(tables.contains(&"emails".to_string()), "got: {:?}", tables);
        assert!(
            tables.contains(&"contacts".to_string()),
            "got: {:?}",
            tables
        );
    }

    // ── Comma-continued FROM lists (SM5-remediation follow-up) ───────

    #[test]
    fn test_comma_continued_from_list_extracts_every_table() {
        // PostgreSQL accepts `FROM a, b` — a FROM/JOIN-keyword-only scan
        // captures `a` and silently misses `b`.
        let refs = referenced_table_aliases("SELECT * FROM contacts c, emails e");
        assert!(
            refs.contains(&("contacts".to_string(), Some("c".to_string()))),
            "got: {refs:?}"
        );
        assert!(
            refs.contains(&("emails".to_string(), Some("e".to_string()))),
            "got: {refs:?}"
        );

        // Three entries, unaliased, still all captured.
        let refs = referenced_table_aliases("SELECT * FROM contacts, emails, templates");
        assert_eq!(refs.len(), 3, "got: {refs:?}");
        for t in ["contacts", "emails", "templates"] {
            assert!(
                refs.iter().any(|(table, _)| table == t),
                "missing {t} in {refs:?}"
            );
        }

        // The list ends at the next clause — nothing after WHERE is a table.
        let refs =
            referenced_table_aliases("SELECT * FROM contacts, emails WHERE workspace_id = $1");
        assert_eq!(refs.len(), 2, "got: {refs:?}");

        // Function-argument commas are not list continuations.
        let refs = referenced_table_aliases(
            "SELECT * FROM generate_series(1, 10) g WHERE g.workspace_id = $1",
        );
        assert_eq!(refs.len(), 1, "got: {refs:?}");
    }

    #[test]
    fn test_comma_continued_from_list_enforces_predicate_per_table() {
        // THE enforcement consequence: with `contacts c, emails e`, a
        // predicate on contacts alone must NOT validate — emails is an
        // unscoped tenanted reference exactly like the JOIN case.
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(
            !svc.validate_query_access(
                "SELECT * FROM contacts c, emails e WHERE c.workspace_id = $1",
                &ctx
            ),
            "a comma list with only ONE tenanted table scoped must be blocked"
        );
        assert!(svc.validate_query_access(
            "SELECT * FROM contacts c, emails e \
             WHERE c.workspace_id = $1 AND e.workspace_id = $2",
            &ctx
        ));
    }

    #[test]
    fn test_rls_statements_include_force() {
        let stmts = rls_statements("\"public\"", "\"emails\"");
        assert!(stmts
            .iter()
            .any(|s| s.contains("ENABLE ROW LEVEL SECURITY")));
        assert!(
            stmts.iter().any(|s| s.contains("FORCE ROW LEVEL SECURITY")),
            "FORCE RLS must be issued so the table owner is also subject to policies: {:?}",
            stmts
        );
        assert_eq!(stmts.len(), 6);
    }

    #[test]
    fn test_evaluate_policies_default_allow_no_policies() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(svc.evaluate_policies(&ctx, "email", "read"));
    }

    #[test]
    fn test_evaluate_policies_deny_overrides() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies_loaded: true,
            policies: vec![DataAccessPolicy {
                id: "p1".into(),
                name: "Deny all writes".into(),
                resource: "email".into(),
                conditions: vec![],
                actions: vec!["write".into()],
                effect: PolicyEffect::Deny,
            }],
        };
        let ctx = make_ctx();
        assert!(!svc.evaluate_policies(&ctx, "email", "write"));
    }

    #[test]
    fn test_evaluate_policies_allow() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies_loaded: true,
            policies: vec![DataAccessPolicy {
                id: "p1".into(),
                name: "Allow reads".into(),
                resource: "email".into(),
                conditions: vec![],
                actions: vec!["read".into()],
                effect: PolicyEffect::Allow,
            }],
        };
        let ctx = make_ctx();
        assert!(svc.evaluate_policies(&ctx, "email", "read"));
    }

    #[test]
    fn test_evaluate_conditions_equals() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "organization_id".into(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("org1"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_not_equals() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "organization_id".into(),
            operator: ConditionOperator::NotEquals,
            value: serde_json::json!("other_org"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_in() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "workspace_id".into(),
            operator: ConditionOperator::In,
            value: serde_json::json!(["ws1", "ws2", "ws3"]),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_not_in() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "workspace_id".into(),
            operator: ConditionOperator::NotIn,
            value: serde_json::json!(["ws99"]),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_contains() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "user_id".into(),
            operator: ConditionOperator::Contains,
            value: serde_json::json!("user"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_starts_with() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "organization_id".into(),
            operator: ConditionOperator::StartsWith,
            value: serde_json::json!("org"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_sanitize_sql_ident() {
        assert_eq!(sanitize_sql_ident("table-name"), "tablename");
        assert_eq!(sanitize_sql_ident("my_table_123"), "my_table_123");
        let long = "x".repeat(100);
        assert_eq!(sanitize_sql_ident(&long).len(), 63);
    }

    #[test]
    fn test_resource_to_table() {
        assert_eq!(resource_to_table("email"), "emails");
        assert_eq!(resource_to_table("contact"), "contacts");
        assert_eq!(resource_to_table("api_key"), "api_keys");
        assert_eq!(resource_to_table("custom"), "__unknown__");
    }

    #[test]
    fn test_get_context_value() {
        let ctx = make_ctx();
        assert_eq!(
            get_context_value(&ctx, "organization_id"),
            Some("org1".into())
        );
        assert_eq!(get_context_value(&ctx, "workspace_id"), Some("ws1".into()));
        assert_eq!(get_context_value(&ctx, "user_id"), Some("user1".into()));
        assert_eq!(
            get_context_value(&ctx, "isolation_level"),
            Some("shared".into())
        );
        assert!(get_context_value(&ctx, "unknown").is_none());
    }

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    fn test_pool() -> PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }
}
