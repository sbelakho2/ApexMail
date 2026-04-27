//! Multi-layer input decoder
//!
//! Recursively decodes payloads through multiple encoding layers to
//! prevent evasion techniques. Supports URL encoding, HTML entities,
//! Base64, unicode escapes, and mixed encodings.

use unicode_normalization::UnicodeNormalization;

/// Canonicalize an input before analysis.
/// Steps:/// 1. Multi-layer decoding (URL/HTML entity/unicode escapes)
/// 2. Unicode NFKC normalization
/// 3. Confusable character folding for common attack tokens
pub fn canonicalize_input(input: &str, max_depth: usize, normalize_unicode: bool) -> String {
    let decoded = decode_payload(input, max_depth);
    if !normalize_unicode {
        return decoded;
    }

    let normalized: String = decoded.nfkc().collect();
    normalized.chars().map(fold_confusable).collect()
}

/// Decode a potentially multi-encoded payload.
/// Applies layers of decoding until no further transformations occur
/// or the maximum recursion depth is reached.
pub fn decode_payload(input: &str, max_depth: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..max_depth {
        let decoded = decode_one_layer(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

/// Apply one pass of all decoders
fn decode_one_layer(input: &str) -> String {
    let step1 = url_decode(input);
    let step2 = html_entity_decode(&step1);
    
    unicode_escape_decode(&step2)
}

/// URL percent-decoding (%XX)
pub fn url_decode(input: &str) -> String {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'%' && i + 2 < len {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(b' ');
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// HTML entity decoding (&amp; &#NNN; &#xHH;)
pub fn html_entity_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        if chars[i] == '&' {
            if let Some(end) = chars[i..].iter().position(|&c| c == ';') {
                let entity: String = chars[i + 1..i + end].iter().collect();
                if let Some(decoded) = decode_html_entity(&entity) {
                    result.push(decoded);
                    i += end + 1;
                    continue;
                }
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

fn decode_html_entity(entity: &str) -> Option<char> {
// Named entities
    match entity {
        "amp" => return Some('&'),
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        "tab" => return Some('\t'),
        "newline" | "NewLine" => return Some('\n'),
        "sol" => return Some('/'),
        "bsol" => return Some('\\'),
        _ => {}
    }
// Numeric (&#NNN;)
    if let Some(num_str) = entity.strip_prefix('#') {
        if num_str.starts_with('x') || num_str.starts_with('X') {
// Hex &#xHH;
            let hex_str = &num_str[1..];
            if let Ok(n) = u32::from_str_radix(hex_str, 16) {
                return char::from_u32(n);
            }
        } else if let Ok(n) = num_str.parse::<u32>() {
            return char::from_u32(n);
        }
    }
    None
}

/// Unicode escape decoding (\uXXXX)
pub fn unicode_escape_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '\\' && i + 5 < len && chars[i + 1] == 'u' {
            let hex_str: String = chars[i + 2..i + 6].iter().collect();
            if let Ok(n) = u32::from_str_radix(&hex_str, 16) {
                if let Some(c) = char::from_u32(n) {
                    result.push(c);
                    i += 6;
                    continue;
                }
            }
        }
        result.push(chars[i]);
        i += 1;
    }

    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn fold_confusable(c: char) -> char {
    match c {
        '\u{FF0F}' | '\u{2215}' | '\u{2044}' => '/',
        '\u{FF0E}' | '\u{2024}' | '\u{3002}' => '.',
        '\u{FF1C}' => '<',
        '\u{FF1E}' => '>',
        '\u{FF07}' | '\u{2019}' => '\'',
        '\u{FF02}' | '\u{201D}' => '"',
        '\u{FF1B}' => ';',
        '\u{FF06}' => '&',
        '\u{FF5C}' => '|',
        '\u{FF04}' => '$',
        '\u{0430}' | '\u{03B1}' => 'a', // Cyrillic/Greek alpha
        '\u{0435}' => 'e', // Cyrillic e
        '\u{043E}' => 'o', // Cyrillic o
        '\u{0440}' => 'p', // Cyrillic er
        '\u{0441}' => 'c', // Cyrillic es
        '\u{0445}' => 'x', // Cyrillic ha
        _ => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("%3Cscript%3E"), "<script>");
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("%27%20OR%201%3D1"), "' OR 1=1");
    }

    #[test]
    fn test_html_entity_decode() {
        assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
        assert_eq!(html_entity_decode("&#60;script&#62;"), "<script>");
        assert_eq!(html_entity_decode("&#x3C;script&#x3E;"), "<script>");
    }

    #[test]
    fn test_unicode_escape() {
        assert_eq!(unicode_escape_decode("\\u003Cscript\\u003E"), "<script>");
    }

    #[test]
    fn test_multi_layer_decode() {
// Double URL-encoded
        let payload = "%253Cscript%253E";
        let decoded = decode_payload(payload, 5);
        assert_eq!(decoded, "<script>");
    }

    #[test]
    fn test_canonicalize_fullwidth_tokens() {
        let payload = "＜script＞alert(1)＜/script＞";
        let canonical = canonicalize_input(payload, 3, true);
        assert_eq!(canonical, "<script>alert(1)</script>");
    }

    #[test]
    fn test_canonicalize_confusable_keyword() {
        let payload = "jаvascript:alert(1)"; // contains Cyrillic 'а'
        let canonical = canonicalize_input(payload, 3, true);
        assert_eq!(canonical, "javascript:alert(1)");
    }
}
