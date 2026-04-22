//! JSON and GraphQL payload inspection for WAF
//!
//! Provides structured parsing of JSON and GraphQL payloads to detect
//! injection attacks hidden in nested structures that regex-based WAFs miss.



/// Result of JSON inspection showing paths to potentially dangerous values
#[derive(Debug, Clone)]
pub struct JsonInspectionResult {
/// All string values found in the JSON, with their paths
    pub string_values: Vec<JsonPathValue>,
/// Whether parsing was successful
    pub parsed_ok: bool,
/// Error message if parsing failed
    pub error: Option<String>,
/// Total field count encountered during parsing
    pub field_count: usize,
}

/// Maximum number of fields/values across the entire parsed document.
/// Prevents exponential fan-out from heavily aliased flat queries (breadth attack).
const MAX_FIELD_COUNT: usize = 5000;
/// Maximum total parse nodes (objects/arrays/scalars) to prevent parser fan-out DoS.
const MAX_NODE_COUNT: usize = 20000;

/// A value extracted from JSON with its path
#[derive(Debug, Clone)]
pub struct JsonPathValue {
/// JSON path (e.g., "$.user.name" or "$[0].query")
    pub path: String,
/// The extracted string value
    pub value: String,
}

/// Extract all string values from a JSON payload for inspection.
/// This allows the WAF to inspect values nested deep in JSON structures.
pub fn extract_json_values(json: &str) -> JsonInspectionResult {
    const MAX_DEPTH: usize = 15; // Prevent stack overflow and query-depth DoS on deeply nested JSON
    
    let mut values = Vec::new();
    let mut field_count: usize = 0;
    let mut node_count: usize = 0;
    let trimmed = json.trim();
    
    if trimmed.is_empty() {
        return JsonInspectionResult {
            string_values: values,
            parsed_ok: true,
            error: None,
            field_count: 0,
        };
    }
    
// Simple recursive parser for JSON values
    let chars: Vec<char> = trimmed.chars().collect();
    let mut pos = 0;
    
    if let Some(first) = chars.first() {
        match first {
            '{' => {
                let result = parse_object(&chars, &mut pos, "$", 0, MAX_DEPTH, &mut field_count, &mut node_count);
                match result {
                    Ok(v) => values.extend(v),
                    Err(e) => {
                        return JsonInspectionResult {
                            string_values: values,
                            parsed_ok: false,
                            error: Some(e),
                            field_count,
                        };
                    }
                }
            }
            '[' => {
                let result = parse_array(&chars, &mut pos, "$", 0, MAX_DEPTH, &mut field_count, &mut node_count);
                match result {
                    Ok(v) => values.extend(v),
                    Err(e) => {
                        return JsonInspectionResult {
                            string_values: values,
                            parsed_ok: false,
                            error: Some(e),
                            field_count,
                        };
                    }
                }
            }
            '"' => {
                if let Ok(s) = parse_string(&chars, &mut pos) {
                    field_count += 1;
                    values.push(JsonPathValue { path: "$".into(), value: s });
                }
            }
            _ => {}
        }
    }
    
    JsonInspectionResult {
        string_values: values,
        parsed_ok: true,
        error: None,
        field_count,
    }
}

fn skip_whitespace(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_whitespace() {
        *pos += 1;
    }
}

fn parse_string(chars: &[char], pos: &mut usize) -> Result<String, String> {
    if *pos >= chars.len() || chars[*pos] != '"' {
        return Err("Expected string".into());
    }
    *pos += 1; // skip opening quote
    
    let mut result = String::new();
    let mut escaped = false;
    
    while *pos < chars.len() {
        let c = chars[*pos];
        *pos += 1;
        
        if escaped {
            match c {
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                'u' => {
// Unicode escape
                    if *pos + 4 <= chars.len() {
                        let hex: String = chars[*pos..*pos + 4].iter().collect();
                        *pos += 4;
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                result.push(ch);
                            }
                        }
                    }
                }
                _ => result.push(c),
            }
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Ok(result);
        } else {
            result.push(c);
        }
    }
    
    Err("Unterminated string".into())
}

fn parse_object(chars: &[char], pos: &mut usize, path: &str, depth: usize, max_depth: usize, field_count: &mut usize, node_count: &mut usize) -> Result<Vec<JsonPathValue>, String> {
    *node_count += 1;
    if *node_count > MAX_NODE_COUNT {
        return Err("Maximum node count exceeded (complexity limit)".into());
    }
    if depth > max_depth {
        return Err("Maximum nesting depth exceeded".into());
    }
    if *field_count > MAX_FIELD_COUNT {
        return Err("Maximum field count exceeded (breadth limit)".into());
    }
    
    let mut values = Vec::new();
    
    if *pos >= chars.len() || chars[*pos] != '{' {
        return Err("Expected object".into());
    }
    *pos += 1;
    
    skip_whitespace(chars, pos);
    
// Empty object
    if *pos < chars.len() && chars[*pos] == '}' {
        *pos += 1;
        return Ok(values);
    }
    
    loop {
        skip_whitespace(chars, pos);
        
// Parse key
        if *pos >= chars.len() || chars[*pos] != '"' {
            return Err("Expected key".into());
        }
        let key = parse_string(chars, pos)?;
        let new_path = format!("{}.{}", path, key);
        *field_count += 1;
        if *field_count > MAX_FIELD_COUNT {
            return Err("Maximum field count exceeded (breadth limit)".into());
        }
        
        skip_whitespace(chars, pos);
        
// Expect colon
        if *pos >= chars.len() || chars[*pos] != ':' {
            return Err("Expected colon".into());
        }
        *pos += 1;
        
        skip_whitespace(chars, pos);
        
// Parse value
        values.extend(parse_value(chars, pos, &new_path, depth + 1, max_depth, field_count, node_count)?);
        
        skip_whitespace(chars, pos);
        
        if *pos >= chars.len() {
            return Err("Unexpected end of object".into());
        }
        
        match chars[*pos] {
            ',' => {
                *pos += 1;
                continue;
            }
            '}' => {
                *pos += 1;
                return Ok(values);
            }
            _ => return Err(format!("Unexpected char in object: {}", chars[*pos])),
        }
    }
}

fn parse_array(chars: &[char], pos: &mut usize, path: &str, depth: usize, max_depth: usize, field_count: &mut usize, node_count: &mut usize) -> Result<Vec<JsonPathValue>, String> {
    *node_count += 1;
    if *node_count > MAX_NODE_COUNT {
        return Err("Maximum node count exceeded (complexity limit)".into());
    }
    if depth > max_depth {
        return Err("Maximum nesting depth exceeded".into());
    }
    if *field_count > MAX_FIELD_COUNT {
        return Err("Maximum field count exceeded (breadth limit)".into());
    }
    
    let mut values = Vec::new();
    
    if *pos >= chars.len() || chars[*pos] != '[' {
        return Err("Expected array".into());
    }
    *pos += 1;
    
    skip_whitespace(chars, pos);
    
// Empty array
    if *pos < chars.len() && chars[*pos] == ']' {
        *pos += 1;
        return Ok(values);
    }
    
    let mut index = 0;
    loop {
        skip_whitespace(chars, pos);
        
        let new_path = format!("{}[{}]", path, index);
        values.extend(parse_value(chars, pos, &new_path, depth + 1, max_depth, field_count, node_count)?);
        index += 1;
        
        skip_whitespace(chars, pos);
        
        if *pos >= chars.len() {
            return Err("Unexpected end of array".into());
        }
        
        match chars[*pos] {
            ',' => {
                *pos += 1;
                continue;
            }
            ']' => {
                *pos += 1;
                return Ok(values);
            }
            _ => return Err(format!("Unexpected char in array: {}", chars[*pos])),
        }
    }
}

fn parse_value(chars: &[char], pos: &mut usize, path: &str, depth: usize, max_depth: usize, field_count: &mut usize, node_count: &mut usize) -> Result<Vec<JsonPathValue>, String> {
    *node_count += 1;
    if *node_count > MAX_NODE_COUNT {
        return Err("Maximum node count exceeded (complexity limit)".into());
    }
    if depth > max_depth {
        return Err("Maximum nesting depth exceeded".into());
    }
    if *field_count > MAX_FIELD_COUNT {
        return Err("Maximum field count exceeded (breadth limit)".into());
    }
    
    skip_whitespace(chars, pos);
    
    if *pos >= chars.len() {
        return Err("Unexpected end of input".into());
    }
    
    match chars[*pos] {
        '"' => {
            let s = parse_string(chars, pos)?;
            *field_count += 1;
            Ok(vec![JsonPathValue { path: path.into(), value: s }])
        }
        '{' => parse_object(chars, pos, path, depth, max_depth, field_count, node_count),
        '[' => parse_array(chars, pos, path, depth, max_depth, field_count, node_count),
        't' | 'f' => {
// true or false
            let word: String = chars[*pos..].iter().take(5).collect();
            if word.starts_with("true") {
                *pos += 4;
            } else if word.starts_with("false") {
                *pos += 5;
            }
            Ok(vec![])
        }
        'n' => {
// null
            *pos += 4;
            Ok(vec![])
        }
        c if c.is_ascii_digit() || c == '-' => {
// Number
            while *pos < chars.len() && (chars[*pos].is_ascii_digit() 
                || chars[*pos] == '.' 
                || chars[*pos] == 'e' 
                || chars[*pos] == 'E'
                || chars[*pos] == '+'
                || chars[*pos] == '-') 
            {
                *pos += 1;
            }
            Ok(vec![])
        }
        _ => Err(format!("Unexpected character: {}", chars[*pos])),
    }
}

/// GraphQL query inspection result
#[derive(Debug, Clone)]
pub struct GraphQLInspectionResult {
/// Extracted operation name
    pub operation_name: Option<String>,
/// Extracted query/mutation type
    pub operation_type: Option<String>,
/// All string arguments found
    pub string_arguments: Vec<GraphQLArgument>,
/// All variable values (from the variables field)
    pub variables: Vec<JsonPathValue>,
/// Whether this looks like valid GraphQL
    pub looks_like_graphql: bool,
/// Estimated number of GraphQL fields in the request
    pub field_count: usize,
/// Maximum observed GraphQL selection-set depth
    pub max_depth: usize,
/// True when field/depth limits are exceeded
    pub limit_exceeded: bool,
}

/// A GraphQL argument with its location
#[derive(Debug, Clone)]
pub struct GraphQLArgument {
/// The field path (e.g., "user.email")
    pub field_path: String,
/// Argument name
    pub arg_name: String,
/// Argument value
    pub value: String,
}

/// Extract arguments and variables from a GraphQL payload.
pub fn extract_graphql_values(body: &str) -> GraphQLInspectionResult {
    let mut result = GraphQLInspectionResult {
        operation_name: None,
        operation_type: None,
        string_arguments: Vec::new(),
        variables: Vec::new(),
        looks_like_graphql: false,
        field_count: 0,
        max_depth: 0,
        limit_exceeded: false,
    };
    
    let trimmed = body.trim();
    
// First, check if this is a JSON-wrapped GraphQL (POST)
    if trimmed.starts_with('{') {
// Try to extract "query" and "variables" fields
        let json_result = extract_json_values(body);
        
// Only treat as JSON-wrapped GraphQL if we found a query or mutation field
        let mut found_query_field = false;
        for jpv in &json_result.string_values {
            if jpv.path == "$.query" || jpv.path == "$.mutation" {
                found_query_field = true;
                result.looks_like_graphql = true;
// Parse the GraphQL query string
                let inner = parse_graphql_query(&jpv.value);
                result.operation_name = inner.operation_name;
                result.operation_type = inner.operation_type;
                result.string_arguments.extend(inner.string_arguments);
                result.field_count = inner.field_count;
                result.max_depth = inner.max_depth;
                result.limit_exceeded = inner.limit_exceeded;
            } else if jpv.path.starts_with("$.variables") {
                result.variables.push(jpv.clone());
            }
        }
        
// If we found variables in the JSON, they're attack surfaces too
        for jpv in json_result.string_values {
            if jpv.path.starts_with("$.variables.") {
                result.variables.push(jpv);
            }
        }
        
// If this wasn't JSON-wrapped GraphQL, try parsing as raw GraphQL
// (e.g., "{ __schema { types { name } } }" is valid GraphQL, not JSON)
        if !found_query_field {
            let inner = parse_graphql_query(body);
            if inner.looks_like_graphql {
                result = inner;
            }
        }
    } else if trimmed.starts_with("query") || trimmed.starts_with("mutation") || trimmed.starts_with("subscription") || trimmed.starts_with("fragment") {
// Raw GraphQL query (GET or direct)
        result.looks_like_graphql = true;
        let inner = parse_graphql_query(body);
        result.operation_name = inner.operation_name;
        result.operation_type = inner.operation_type;
        result.string_arguments = inner.string_arguments;
        result.field_count = inner.field_count;
        result.max_depth = inner.max_depth;
        result.limit_exceeded = inner.limit_exceeded;
    }
    
    result
}

fn parse_graphql_query(query: &str) -> GraphQLInspectionResult {
    let mut result = GraphQLInspectionResult {
        operation_name: None,
        operation_type: None,
        string_arguments: Vec::new(),
        variables: Vec::new(),
        looks_like_graphql: false,
        field_count: 0,
        max_depth: 0,
        limit_exceeded: false,
    };
    
    let trimmed = query.trim();
    
// Detect operation type
    if trimmed.starts_with("query") {
        result.operation_type = Some("query".into());
        result.looks_like_graphql = true;
    } else if trimmed.starts_with("mutation") {
        result.operation_type = Some("mutation".into());
        result.looks_like_graphql = true;
    } else if trimmed.starts_with("subscription") {
        result.operation_type = Some("subscription".into());
        result.looks_like_graphql = true;
    } else if trimmed.starts_with("fragment") {
// GraphQL fragment definition
        result.operation_type = Some("fragment".into());
        result.looks_like_graphql = true;
    } else if trimmed.starts_with('{') {
        result.operation_type = Some("query".into());
        result.looks_like_graphql = true;
    }
    
// Extract string arguments (simplified regex-like approach)
// Look for patterns like:field(arg:"value")
    let mut in_string = false;
    let mut string_start = 0;
    let mut current_arg = String::new();
    let current_field = String::new();
    let chars: Vec<char> = trimmed.chars().collect();
    
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        
        if !in_string {
            if c == '"' {
                in_string = true;
                string_start = i + 1;
                
// Try to find the argument name before this string
// Look backwards for ':'
                let before: String = chars[..i].iter().collect();
                if let Some(colon_pos) = before.rfind(':') {
                    let before_colon = before[..colon_pos].trim_end();
// Extract the argument name (last word before :)
                    current_arg = before_colon
                        .chars()
                        .rev()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                }
            }
        } else {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
                let value: String = chars[string_start..i].iter().collect();
                result.string_arguments.push(GraphQLArgument {
                    field_path: current_field.clone(),
                    arg_name: current_arg.clone(),
                    value,
                });
                current_arg.clear();
            }
        }
        i += 1;
    }

    let (field_count, max_depth) = estimate_graphql_complexity(trimmed);
    result.field_count = field_count;
    result.max_depth = max_depth;
    result.limit_exceeded = field_count > MAX_FIELD_COUNT || max_depth > 15;
    
    result
}

fn estimate_graphql_complexity(query: &str) -> (usize, usize) {
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    let mut field_count = 0usize;
    let mut in_string = false;
    let mut escape = false;
    let mut in_arg_list = false;
    let mut token = String::new();

    let flush_identifier = |tok: &mut String, in_args: bool, in_str: bool, fields: &mut usize| {
        if in_str || in_args || tok.is_empty() {
            tok.clear();
            return;
        }
        let is_keyword = matches!(tok.as_str(), "query" | "mutation" | "subscription" | "fragment" | "on");
        if !is_keyword {
            *fields += 1;
        }
        tok.clear();
    };

    for c in query.chars() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => {
                flush_identifier(&mut token, in_arg_list, in_string, &mut field_count);
                in_string = true;
            }
            '{' => {
                flush_identifier(&mut token, in_arg_list, in_string, &mut field_count);
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            '}' => {
                flush_identifier(&mut token, in_arg_list, in_string, &mut field_count);
                depth = depth.saturating_sub(1);
            }
            '(' => {
                flush_identifier(&mut token, in_arg_list, in_string, &mut field_count);
                in_arg_list = true;
            }
            ')' => {
                flush_identifier(&mut token, in_arg_list, in_string, &mut field_count);
                in_arg_list = false;
            }
            c if c.is_alphanumeric() || c == '_' => token.push(c),
            _ => flush_identifier(&mut token, in_arg_list, in_string, &mut field_count),
        }
    }
    flush_identifier(&mut token, in_arg_list, in_string, &mut field_count);

    (field_count, max_depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_json() {
        let json = r#"{"name": "test", "value": "hello"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        assert_eq!(result.string_values.len(), 2);
    }

    #[test]
    fn test_nested_json() {
        let json = r#"{"user": {"name": "alice", "email": "alice@test.com"}, "query": "SELECT * FROM users"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
// Should find name, email, query
        assert!(result.string_values.iter().any(|v| v.value == "SELECT * FROM users"));
    }

    #[test]
    fn test_json_array() {
        let json = r#"[{"id": "1"}, {"id": "2"}]"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        assert_eq!(result.string_values.len(), 2);
        assert!(result.string_values.iter().any(|v| v.path == "$[0].id"));
    }

    #[test]
    fn test_sqli_in_json() {
        let json = r#"{"search": "'; DROP TABLE users; --"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        assert!(result.string_values.iter().any(|v| v.value.contains("DROP TABLE")));
    }

    #[test]
    fn test_graphql_query() {
        let query = r#"query { user(id: "1' OR '1'='1") { name } }"#;
        let result = extract_graphql_values(query);
        assert!(result.looks_like_graphql);
        assert!(result.string_arguments.iter().any(|a| a.value.contains("OR")));
    }

    #[test]
    fn test_graphql_json_wrapper() {
        let json = r#"{"query": "query { user(id: \"123\") { name } }", "variables": {"userId": "1' OR 1=1"}}"#;
        let result = extract_graphql_values(json);
        assert!(result.looks_like_graphql);
    }

    #[test]
    fn test_unicode_escape() {
        let json = r#"{"payload": "\u003cscript\u003ealert(1)\u003c/script\u003e"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
// The unicode should decode to <script>alert(1)</script>
        assert!(result.string_values.iter().any(|v| v.value.contains("<script>")));
    }
}
