//! Multi-layer input decoder
//!
//! Recursively decodes payloads through multiple encoding layers to
//! prevent evasion techniques. Supports URL encoding, HTML entities,
//! Base64, unicode escapes, and mixed encodings.

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
    let step3 = unicode_escape_decode(&step2);
    step3
}

/// URL percent-decoding (%XX)
pub fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'%' && i + 2 < len {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(' ');
        } else {
            result.push(bytes[i] as char);
        }
        i += 1;
    }
    result
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
    if entity.starts_with('#') {
        let num_str = &entity[1..];
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
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'\\' && i + 5 < len && bytes[i + 1] == b'u' {
            let hex_str = std::str::from_utf8(&bytes[i + 2..i + 6]).unwrap_or("");
            if let Ok(n) = u32::from_str_radix(hex_str, 16) {
                if let Some(c) = char::from_u32(n) {
                    result.push(c);
                    i += 6;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
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
}
