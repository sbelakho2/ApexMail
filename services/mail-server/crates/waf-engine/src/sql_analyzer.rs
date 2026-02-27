//! SQL injection detection via structural (AST-level) analysis
//!
//! Instead of relying on regex patterns that attackers routinely bypass,
//! this module tokenizes SQL fragments and detects structural manipulation:
//!
//! - Tautologies (`1=1`, `'a'='a'`, `1<2`)
//! - Union-based injection (`UNION SELECT`)
//! - Stacked queries (`;DROP TABLE`)
//! - Comment-based evasion (`/**/`, `--`, `#`)
//! - Blind injection patterns (`AND SLEEP(`, `BENCHMARK(`)
//! - String termination (`' OR`, `" OR`)

use crate::{AttackCategory, MatchLocation, RuleMatch};

/// SQL token types
#[derive(Debug, Clone, PartialEq)]
enum SqlToken {
    Keyword(SqlKeyword),
    Operator(SqlOp),
    StringLiteral(String),
    NumberLiteral(f64),
    Identifier(String),
    Comment,
    Semicolon,
    OpenParen,
    CloseParen,
    Comma,
    Whitespace,
    Unknown(char),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SqlKeyword {
    Select, From, Where, And, Or, Union, All, Insert, Update, Delete,
    Drop, Alter, Create, Table, Into, Values, Set, Exec,
    Having, Group, Order, By, Like, In, Between, Is, Null, Not,
    Sleep, Benchmark, Waitfor, Delay, If, Case, When, Then, Else,
    Load, File, Outfile, Dumpfile, Information,
    // PostgreSQL/database-specific blind injection functions
    PgSleep,       // pg_sleep() - PostgreSQL
    DbmsLock,      // dbms_lock.sleep() - Oracle
    UtlHttp,       // UTL_HTTP.request() - Oracle
    Xor,           // XOR operator (MySQL boolean injection)
    Regexp, Rlike, // REGEXP/RLIKE (MySQL pattern matching)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SqlOp {
    Eq,      // =
    Neq,     // != or <>
    Lt,      // <
    Gt,      // >
    LtEq,    // <=
    GtEq,    // >=
    Plus,
    Minus,
    Star,
    Slash,
    Pipe,    // ||
    Ampersand,
}

/// Analyze input for SQL injection patterns.
/// Returns a list of detected threats with severity scores.
pub fn analyze_sqli(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::with_capacity(7);
    let lower = input.to_lowercase();
    let tokens = tokenize_sql(&lower);

    // Detection 1: Tautology (e.g., 1=1, 'a'='a')
    if let Some(score) = detect_tautology(&tokens) {
        results.push(RuleMatch {
            rule_id: 942100,
            category: AttackCategory::SqlInjection,
            score,
            message: "SQL tautology detected (e.g., 1=1, 'a'='a')".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 2: UNION SELECT
    if detect_union_select(&tokens) {
        results.push(RuleMatch {
            rule_id: 942200,
            category: AttackCategory::SqlInjection,
            score: 5,
            message: "UNION-based SQL injection detected".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 3: Stacked queries
    if detect_stacked_queries(&tokens) {
        results.push(RuleMatch {
            rule_id: 942300,
            category: AttackCategory::SqlInjection,
            score: 5,
            message: "Stacked SQL query detected (semicolon + keyword)".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 4: Comment-based evasion
    if detect_comment_evasion(&lower) {
        results.push(RuleMatch {
            rule_id: 942400,
            category: AttackCategory::SqlInjection,
            score: 3,
            message: "SQL comment-based evasion detected".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 5: Blind / time-based injection
    if detect_blind_injection(&tokens) {
        results.push(RuleMatch {
            rule_id: 942500,
            category: AttackCategory::SqlInjection,
            score: 5,
            message: "Blind/time-based SQL injection detected (SLEEP/BENCHMARK/WAITFOR)".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 6: String termination + boolean logic
    if detect_string_termination_logic(&tokens) {
        results.push(RuleMatch {
            rule_id: 942600,
            category: AttackCategory::SqlInjection,
            score: 4,
            message: "SQL string termination with boolean logic detected".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 7: Dangerous functions/data exfiltration
    if detect_dangerous_functions(&tokens) {
        results.push(RuleMatch {
            rule_id: 942700,
            category: AttackCategory::SqlInjection,
            score: 5,
            message: "Dangerous SQL function detected (LOAD_FILE, INTO OUTFILE, etc.)".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    results
}

/// Tokenize an input string into SQL tokens
fn tokenize_sql(input: &str) -> Vec<SqlToken> {
    let mut tokens = Vec::with_capacity(input.len().min(256));
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Skip whitespace
        if chars[i].is_whitespace() {
            tokens.push(SqlToken::Whitespace);
            while i < len && chars[i].is_whitespace() {
                i += 1;
            }
            continue;
        }

        // Comments: -- or /* ... */ or #
        if i + 1 < len && chars[i] == '-' && chars[i + 1] == '-' {
            tokens.push(SqlToken::Comment);
            while i < len && chars[i] != '\n' { i += 1; }
            continue;
        }
        if chars[i] == '#' {
            tokens.push(SqlToken::Comment);
            while i < len && chars[i] != '\n' { i += 1; }
            continue;
        }
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
            tokens.push(SqlToken::Comment);
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') { i += 1; }
            if i + 1 < len { i += 2; }
            continue;
        }

        // String literals
        if chars[i] == '\'' || chars[i] == '"' {
            let quote = chars[i];
            i += 1;
            let start = i;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' { i += 1; }
                i += 1;
            }
            if i < len {
                // Properly terminated string literal
                let s: String = chars[start..i].iter().collect();
                tokens.push(SqlToken::StringLiteral(s));
                i += 1;
            } else {
                // Unterminated quote — likely an injection breaking out of a string
                // Emit the quote as unknown and re-parse from after the quote
                tokens.push(SqlToken::Unknown(quote));
                i = start; // resume tokenizing after the opening quote
            }
            continue;
        }

        // Hexadecimal literals: 0x1A, 0xFF, etc.
        // Without this, `0x31=0x31` parses as NumberLiteral(0) + Identifier(x31)
        // and the tautology checker never sees two equal numbers.
        if chars[i] == '0'
            && i + 1 < len
            && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
            && i + 2 < len
            && chars[i + 2].is_ascii_hexdigit()
        {
            i += 2; // consume '0x'
            let start = i;
            while i < len && chars[i].is_ascii_hexdigit() { i += 1; }
            let hex_str: String = chars[start..i].iter().collect();
            let val = u64::from_str_radix(&hex_str, 16).unwrap_or(0) as f64;
            tokens.push(SqlToken::NumberLiteral(val));
            continue;
        }

        // Decimal / float numbers
        if chars[i].is_ascii_digit() || (chars[i] == '.' && i + 1 < len && chars[i + 1].is_ascii_digit()) {
            let start = i;
            while i < len && (chars[i].is_ascii_digit() || chars[i] == '.') { i += 1; }
            let num_str: String = chars[start..i].iter().collect();
            let val = num_str.parse::<f64>().unwrap_or(0.0);
            tokens.push(SqlToken::NumberLiteral(val));
            continue;
        }

        // Operators
        match chars[i] {
            '=' => { tokens.push(SqlToken::Operator(SqlOp::Eq)); i += 1; }
            '!' if i + 1 < len && chars[i + 1] == '=' => {
                tokens.push(SqlToken::Operator(SqlOp::Neq)); i += 2;
            }
            '<' if i + 1 < len && chars[i + 1] == '>' => {
                tokens.push(SqlToken::Operator(SqlOp::Neq)); i += 2;
            }
            '<' if i + 1 < len && chars[i + 1] == '=' => {
                tokens.push(SqlToken::Operator(SqlOp::LtEq)); i += 2;
            }
            '<' => { tokens.push(SqlToken::Operator(SqlOp::Lt)); i += 1; }
            '>' if i + 1 < len && chars[i + 1] == '=' => {
                tokens.push(SqlToken::Operator(SqlOp::GtEq)); i += 2;
            }
            '>' => { tokens.push(SqlToken::Operator(SqlOp::Gt)); i += 1; }
            '+' => { tokens.push(SqlToken::Operator(SqlOp::Plus)); i += 1; }
            '-' => { tokens.push(SqlToken::Operator(SqlOp::Minus)); i += 1; }
            '*' => { tokens.push(SqlToken::Operator(SqlOp::Star)); i += 1; }
            '/' => { tokens.push(SqlToken::Operator(SqlOp::Slash)); i += 1; }
            '|' if i + 1 < len && chars[i + 1] == '|' => {
                tokens.push(SqlToken::Operator(SqlOp::Pipe)); i += 2;
            }
            '&' => { tokens.push(SqlToken::Operator(SqlOp::Ampersand)); i += 1; }
            ';' => { tokens.push(SqlToken::Semicolon); i += 1; }
            '(' => { tokens.push(SqlToken::OpenParen); i += 1; }
            ')' => { tokens.push(SqlToken::CloseParen); i += 1; }
            ',' => { tokens.push(SqlToken::Comma); i += 1; }
            _ if chars[i].is_alphanumeric() || chars[i] == '_' => {
                let start = i;
                while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') { i += 1; }
                let word: String = chars[start..i].iter().collect();
                let word_lower = word.to_lowercase();
                if let Some(kw) = match_keyword(&word_lower) {
                    tokens.push(SqlToken::Keyword(kw));
                } else {
                    tokens.push(SqlToken::Identifier(word));
                }
            }
            other => { tokens.push(SqlToken::Unknown(other)); i += 1; }
        }
    }

    tokens
}

fn match_keyword(word: &str) -> Option<SqlKeyword> {
    match word {
        "select" => Some(SqlKeyword::Select),
        "from" => Some(SqlKeyword::From),
        "where" => Some(SqlKeyword::Where),
        "and" => Some(SqlKeyword::And),
        "or" => Some(SqlKeyword::Or),
        "union" => Some(SqlKeyword::Union),
        "insert" => Some(SqlKeyword::Insert),
        "update" => Some(SqlKeyword::Update),
        "delete" => Some(SqlKeyword::Delete),
        "drop" => Some(SqlKeyword::Drop),
        "alter" => Some(SqlKeyword::Alter),
        "create" => Some(SqlKeyword::Create),
        "table" => Some(SqlKeyword::Table),
        "into" => Some(SqlKeyword::Into),
        "values" => Some(SqlKeyword::Values),
        "set" => Some(SqlKeyword::Set),
        "exec" | "execute" => Some(SqlKeyword::Exec),
        "having" => Some(SqlKeyword::Having),
        "group" => Some(SqlKeyword::Group),
        "order" => Some(SqlKeyword::Order),
        "by" => Some(SqlKeyword::By),
        "like" => Some(SqlKeyword::Like),
        "in" => Some(SqlKeyword::In),
        "between" => Some(SqlKeyword::Between),
        "is" => Some(SqlKeyword::Is),
        "null" => Some(SqlKeyword::Null),
        "not" => Some(SqlKeyword::Not),
        "sleep" => Some(SqlKeyword::Sleep),
        "benchmark" => Some(SqlKeyword::Benchmark),
        "waitfor" => Some(SqlKeyword::Waitfor),
        "delay" => Some(SqlKeyword::Delay),
        "if" => Some(SqlKeyword::If),
        "case" => Some(SqlKeyword::Case),
        "when" => Some(SqlKeyword::When),
        "then" => Some(SqlKeyword::Then),
        "else" => Some(SqlKeyword::Else),
        "all" => Some(SqlKeyword::All),
        "load" | "load_file" => Some(SqlKeyword::Load),
        "file" => Some(SqlKeyword::File),
        "outfile" => Some(SqlKeyword::Outfile),
        "dumpfile" => Some(SqlKeyword::Dumpfile),
        "information_schema" => Some(SqlKeyword::Information),
        // Database-specific blind injection functions
        "pg_sleep" => Some(SqlKeyword::PgSleep),
        "dbms_lock" => Some(SqlKeyword::DbmsLock),
        "utl_http" => Some(SqlKeyword::UtlHttp),
        "xor" => Some(SqlKeyword::Xor),
        "regexp" => Some(SqlKeyword::Regexp),
        "rlike" => Some(SqlKeyword::Rlike),
        _ => None,
    }
}

/// Detect tautology patterns (e.g., 1=1, 'a'='a')
fn detect_tautology(tokens: &[SqlToken]) -> Option<u32> {
    let significant: Vec<&SqlToken> = tokens.iter()
        .filter(|t| !matches!(t, SqlToken::Whitespace | SqlToken::Comment))
        .collect();

    for window in significant.windows(3) {
        match (&window[0], &window[1], &window[2]) {
            // Number = Number (same value)
            (SqlToken::NumberLiteral(a), SqlToken::Operator(SqlOp::Eq), SqlToken::NumberLiteral(b)) => {
                if (a - b).abs() < f64::EPSILON {
                    return Some(5);
                }
            }
            // String = String (any value): injected literal-to-literal comparison.
            // 'a'='a', 'x'='y', 'admin'='admin' — all indicate injection; legitimate
            // queries compare a column against a literal, never literal against literal.
            (SqlToken::StringLiteral(_), SqlToken::Operator(SqlOp::Eq), SqlToken::StringLiteral(_)) => {
                return Some(5);
            }
            // String comparison with inequality operators: 'z'>'a', 'Z'>='A', etc.
            // Catches tautology-style injections via SQL lexicographic ordering.
            // Use a guard instead of nested OR patterns for maximum compatibility.
            (SqlToken::StringLiteral(_), SqlToken::Operator(op), SqlToken::StringLiteral(_))
                if matches!(op, SqlOp::Lt | SqlOp::Gt | SqlOp::LtEq | SqlOp::GtEq | SqlOp::Neq) =>
            {
                return Some(5);
            }
            // Number < Number (always true like 1<2)
            (SqlToken::NumberLiteral(a), SqlToken::Operator(SqlOp::Lt), SqlToken::NumberLiteral(b)) => {
                if a < b {
                    return Some(4);
                }
            }
            // Number > Number (always true like 2>1)
            (SqlToken::NumberLiteral(a), SqlToken::Operator(SqlOp::Gt), SqlToken::NumberLiteral(b)) => {
                if a > b {
                    return Some(4);
                }
            }
            _ => {}
        }
    }

    // Greedy-pair tokenizer artefact: `'z'>'a'` tokenizes as
    //   Identifier("z") + StringLiteral(">") + Identifier("a")
    // because the lexer wraps the comparison operator between adjacent quote pairs.
    // A string literal whose ENTIRE content is a comparison operator is a unique
    // indicator of an injected string-comparison tautology — never valid SQL.
    for token in &significant {
        if let SqlToken::StringLiteral(s) = token {
            if matches!(s.as_str(), ">" | "<" | ">=" | "<=" | "!=" | "<>") {
                return Some(5);
            }
        }
    }

    None
}

/// Detect UNION [ALL] SELECT injection
/// Handles both `UNION SELECT` and `UNION ALL SELECT` (evasion variant)
fn detect_union_select(tokens: &[SqlToken]) -> bool {
    let significant: Vec<&SqlToken> = tokens.iter()
        .filter(|t| !matches!(t, SqlToken::Whitespace | SqlToken::Comment))
        .collect();

    // Check 2-token window: UNION SELECT
    for window in significant.windows(2) {
        if matches!(window[0], SqlToken::Keyword(SqlKeyword::Union))
            && matches!(window[1], SqlToken::Keyword(SqlKeyword::Select))
        {
            return true;
        }
    }

    // Check 3-token window: UNION ALL SELECT (previously bypassed the 2-token check)
    for window in significant.windows(3) {
        if matches!(window[0], SqlToken::Keyword(SqlKeyword::Union))
            && matches!(window[1], SqlToken::Keyword(SqlKeyword::All))
            && matches!(window[2], SqlToken::Keyword(SqlKeyword::Select))
        {
            return true;
        }
    }

    false
}

/// Detect stacked queries (semicolon followed by SQL keyword)
///
/// Uses a forward-scan rather than a 2-token window so that interleaved tokens
/// like parentheses (`; (DROP TABLE users)`) do not defeat detection.
fn detect_stacked_queries(tokens: &[SqlToken]) -> bool {
    let significant: Vec<&SqlToken> = tokens.iter()
        .filter(|t| !matches!(t, SqlToken::Whitespace | SqlToken::Comment))
        .collect();

    let mut post_semicolon = false;
    for token in &significant {
        match token {
            SqlToken::Semicolon => { post_semicolon = true; }
            SqlToken::Keyword(
                SqlKeyword::Select | SqlKeyword::Insert | SqlKeyword::Update |
                SqlKeyword::Delete | SqlKeyword::Drop | SqlKeyword::Alter |
                SqlKeyword::Create | SqlKeyword::Exec
            ) if post_semicolon => { return true; }
            _ => {}
        }
    }
    false
}

/// Detect inline comment evasion (e.g., UN/**/ION SE/**/LECT)
/// 
/// Works by stripping all inline comments and checking if the resulting
/// string contains SQL keywords, which indicates evasion was attempted.
fn detect_comment_evasion(input: &str) -> bool {
    // Check for MySQL conditional comments (always suspicious)
    if input.contains("/*!") {
        return true;
    }
    
    // If no SQL comment markers, no evasion possible
    if !input.contains("/*") && !input.contains("--") && !input.contains('#') {
        return false;
    }
    
    // Strip comments and compare a compacted representation (letters/digits only).
    // This catches token stitching attacks such as:
    //   UN--x\nION SE--y\nLECT
    // where post-strip text effectively becomes UNION SELECT.
    let collapsed = strip_sql_comments(input);

    let compact = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };

    let input_compact = compact(input);
    let collapsed_compact = compact(&collapsed);

    let input_lower = input.to_lowercase();
    let collapsed_lower = collapsed.to_lowercase();

    // Classic keyword stitching via comments, e.g. UN/**/ION or SE/**/LECT.
    let dangerous_keywords = [
        "union", "select", "insert", "update", "delete", "drop",
        "alter", "create", "exec", "execute", "sleep", "benchmark",
        "waitfor", "load_file", "outfile", "pg_sleep",
    ];
    if dangerous_keywords
        .iter()
        .any(|kw| collapsed_lower.contains(kw) && !input_lower.contains(kw))
    {
        return true;
    }

    if input_compact == collapsed_compact {
        return false;
    }

    let dangerous_sequences = [
        "unionselect",
        "insertinto",
        "droptable",
        "truncate",
        "loadfile",
        "outfile",
        "benchmark",
        "waitfordelay",
        "pgsleep",
    ];

    dangerous_sequences.iter().any(|seq| {
        collapsed_compact.contains(seq) && !input_compact.contains(seq)
    })
}

/// Strip SQL comments from input, collapsing adjacent text.
///
/// Handles:
/// - `/* ... */` block comments
/// - `-- ...` line comments
/// - `# ...` line comments
fn strip_sql_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < chars.len() {
        let c = chars[i];

        if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            result.push(c);
            i += 1;
            continue;
        }
        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            result.push(c);
            i += 1;
            continue;
        }

        if !in_single_quote && !in_double_quote {
            // Block comment: /* ... */
            if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
                i += 2;
                while i + 1 < chars.len() {
                    if chars[i] == '*' && chars[i + 1] == '/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // Line comment: -- ...
            if c == '-' && i + 1 < chars.len() && chars[i + 1] == '-' {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }

            // Line comment: # ...
            if c == '#' {
                i += 1;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
        }

        result.push(c);
        i += 1;
    }

    result
}

/// Detect blind/time-based injection
/// 
/// Covers time-based blind injection across multiple database platforms:
/// - MySQL: SLEEP(), BENCHMARK()
/// - MSSQL: WAITFOR DELAY
/// - PostgreSQL: pg_sleep()
/// - Oracle: dbms_lock.sleep(), UTL_HTTP.request()
fn detect_blind_injection(tokens: &[SqlToken]) -> bool {
    for token in tokens {
        if matches!(token, SqlToken::Keyword(
            SqlKeyword::Sleep | SqlKeyword::Benchmark | SqlKeyword::Waitfor |
            SqlKeyword::Delay | SqlKeyword::PgSleep | SqlKeyword::DbmsLock |
            SqlKeyword::UtlHttp
        )) {
            return true;
        }
    }
    false
}

/// Detect string termination followed by boolean logic
fn detect_string_termination_logic(tokens: &[SqlToken]) -> bool {
    let significant: Vec<&SqlToken> = tokens.iter()
        .filter(|t| !matches!(t, SqlToken::Whitespace | SqlToken::Comment))
        .collect();

    for window in significant.windows(2) {
        if matches!(window[0], SqlToken::StringLiteral(_))
            && matches!(window[1], SqlToken::Keyword(SqlKeyword::Or | SqlKeyword::And))
        {
            return true;
        }
    }
    false
}

/// Detect dangerous functions (LOAD_FILE, INTO OUTFILE, etc.)
fn detect_dangerous_functions(tokens: &[SqlToken]) -> bool {
    for token in tokens {
        if matches!(token, SqlToken::Keyword(
            SqlKeyword::Load | SqlKeyword::Outfile | SqlKeyword::Dumpfile
        )) {
            return true;
        }
    }
    // Check for INFORMATION_SCHEMA access
    for token in tokens {
        if matches!(token, SqlToken::Keyword(SqlKeyword::Information)) {
            return true;
        }
    }
    false
}

/// Safely truncate a string at character boundary (not byte offset).
/// Prevents panic on multi-byte UTF-8 sequences.
fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => format!("{}...", &s[..byte_idx]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MatchLocation;

    #[test]
    fn test_tautology_detection() {
        let results = analyze_sqli("' OR 1=1 --", MatchLocation::QueryParam("q".into()));
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.rule_id == 942100));
    }

    #[test]
    fn test_union_select() {
        let results = analyze_sqli("1 UNION SELECT username, password FROM users", MatchLocation::QueryParam("id".into()));
        assert!(results.iter().any(|r| r.rule_id == 942200));
    }

    #[test]
    fn test_stacked_query() {
        let results = analyze_sqli("1; DROP TABLE users", MatchLocation::QueryParam("id".into()));
        assert!(results.iter().any(|r| r.rule_id == 942300));
    }

    #[test]
    fn test_blind_injection() {
        let results = analyze_sqli("1 AND SLEEP(5)", MatchLocation::QueryParam("id".into()));
        assert!(results.iter().any(|r| r.rule_id == 942500));
    }

    #[test]
    fn test_clean_input_no_false_positive() {
        let results = analyze_sqli("John O'Brien", MatchLocation::QueryParam("name".into()));
        // Should NOT trigger tautology or union
        assert!(results.iter().all(|r| r.rule_id != 942100 && r.rule_id != 942200));
    }

    #[test]
    fn test_comment_evasion() {
        let results = analyze_sqli("UN/**/ION SE/**/LECT 1,2,3", MatchLocation::Body);
        assert!(results.iter().any(|r| r.rule_id == 942400));
    }

    #[test]
    fn test_union_all_select_bypasses_fixed() {
        // Previously this bypassed the 2-token window check
        let results = analyze_sqli("1 UNION ALL SELECT username, password FROM users", MatchLocation::QueryParam("id".into()));
        assert!(results.iter().any(|r| r.rule_id == 942200),
            "UNION ALL SELECT must be detected, got: {:?}", results.iter().map(|r| r.rule_id).collect::<Vec<_>>());
    }

    #[test]
    fn test_union_select_variants() {
        // UNION SELECT (basic)
        let r = analyze_sqli("1 UNION SELECT 1,2,3", MatchLocation::QueryParam("x".into()));
        assert!(r.iter().any(|r| r.rule_id == 942200), "UNION SELECT should be caught");

        // UNION ALL SELECT (evasion)
        let r2 = analyze_sqli("1 UNION ALL SELECT NULL,NULL,NULL--", MatchLocation::QueryParam("x".into()));
        assert!(r2.iter().any(|r| r.rule_id == 942200), "UNION ALL SELECT should be caught");
    }

    #[test]
    fn test_string_tautology_gt() {
        let results = analyze_sqli("alice' OR 'z'>'a'--", MatchLocation::QueryParam("q".into()));
        assert!(
            results.iter().any(|r| r.rule_id == 942100),
            "String comparison tautology 'z'>'a' must fire rule 942100"
        );
    }

    #[test]
    fn test_string_tautology_neq() {
        let results = analyze_sqli("active' OR 'x'!='y'--", MatchLocation::QueryParam("f".into()));
        assert!(
            results.iter().any(|r| r.rule_id == 942100),
            "String NEQ tautology 'x'!='y' must fire rule 942100"
        );
    }

    #[test]
    fn test_hash_comment_evasion_detected() {
        let results = analyze_sqli("UN#x\nION SEL#y\nECT 1,2,3", MatchLocation::Body);
        assert!(results.iter().any(|r| r.rule_id == 942400));
    }

    #[test]
    fn test_double_dash_comment_evasion_detected() {
        let results = analyze_sqli("UN--x\nION SE--y\nLECT 1,2,3", MatchLocation::Body);
        assert!(results.iter().any(|r| r.rule_id == 942400));
    }
}

