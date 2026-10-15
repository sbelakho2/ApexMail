//! A minimal, strict `multipart/form-data` reader for the compatibility
//! surface.
//!
//! Mailgun's `POST /v3/{domain}/messages` accepts an `application/x-www-form-urlencoded`
//! body AND a `multipart/form-data` body (file parts for `attachment`). The
//! workspace's `axum` build carries no `multipart` feature (deliberately, see
//! the workspace manifest), and the parser this surface needs is the narrow
//! RFC 2046 subset below — boundaries, `Content-Disposition` parameters and
//! raw part bytes. It is therefore implemented here, with unit tests covering
//! the adversarial cases (missing boundary, unterminated body, boundary text
//! inside a part's payload, quoted/escaped parameters, LF-only line endings).
//!
//! Every failure is a named string the caller renders in the provider's error
//! shape — a malformed body is never silently accepted as an empty form.

/// One decoded `multipart/form-data` part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MultipartPart {
    /// `Content-Disposition; name="…"` — always present on a form-data part.
    pub name: String,
    /// `filename="…"` when the part is a file upload (absent for plain
    /// fields, and for a file part that carries no filename).
    pub filename: Option<String>,
    /// The part's own `Content-Type` header, when present.
    pub content_type: Option<String>,
    /// The raw payload bytes.
    pub body: Vec<u8>,
}

impl MultipartPart {
    /// The payload as UTF-8 text (form fields are text by contract; an
    /// invalid encoding is a named refusal at the call site).
    pub(crate) fn text(&self) -> Result<&str, String> {
        std::str::from_utf8(&self.body)
            .map_err(|_| format!("multipart field '{}' is not valid UTF-8 text", self.name))
    }
}

/// The `boundary` parameter of a `multipart/form-data` Content-Type.
pub(crate) fn boundary_from_content_type(content_type: &str) -> Result<String, String> {
    // `boundary` is not required to be the first parameter
    // (`multipart/form-data; charset=utf-8; boundary=…`), so every parameter
    // after the media type is scanned.
    for parameter in content_type.split(';').skip(1) {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("boundary") {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or(value);
            if value.is_empty() {
                return Err("multipart/form-data requires a non-empty boundary parameter".into());
            }
            return Ok(value.to_string());
        }
    }
    Err("multipart/form-data requires a boundary parameter".into())
}

/// Parse a `multipart/form-data` body.
///
/// Grammar accepted (RFC 2046 §5.1.1), with LF-only lines tolerated:
///
/// ```text
/// --boundary CRLF part CRLF --boundary CRLF part CRLF --boundary--
/// ```
///
/// A part is `headers CRLF CRLF payload`; the CRLF that precedes a delimiter
/// belongs to the delimiter, not to the payload.
pub(crate) fn parse_multipart(body: &[u8], boundary: &str) -> Result<Vec<MultipartPart>, String> {
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();

    // The first delimiter must open the body (leading CRLF is tolerated).
    let mut cursor = if body.starts_with(delimiter) {
        delimiter.len()
    } else {
        match find(body, 0, delimiter) {
            Some(index) if index == 2 && body.starts_with(b"\r\n") => index + delimiter.len(),
            Some(index) if index == 1 && body.starts_with(b"\n") => index + delimiter.len(),
            _ => return Err("the multipart body does not start with its declared boundary".into()),
        }
    };

    let mut parts = Vec::new();
    loop {
        // A closing delimiter (`--boundary--`) terminates the body.
        if body[cursor..].starts_with(b"--") {
            return Ok(parts);
        }
        if body[cursor..].starts_with(b"\r\n") {
            cursor += 2;
        } else if body[cursor..].starts_with(b"\n") {
            cursor += 1;
        } else if cursor == body.len() {
            return Err("the multipart body is unterminated (missing closing delimiter)".into());
        } else {
            return Err("a multipart delimiter is not followed by a line break".into());
        }

        // The part ends at the CRLF that precedes the NEXT delimiter.
        let next = find_delimiter(body, cursor, delimiter).ok_or_else(|| {
            "the multipart body is unterminated (missing closing delimiter)".to_string()
        })?;
        let part_bytes = &body[cursor..next];
        parts.push(parse_part(part_bytes)?);
        // Skip the line break the delimiter search consumed.
        cursor = next;
        if body[cursor..].starts_with(b"\r\n") {
            cursor += 2;
        } else if body[cursor..].starts_with(b"\n") {
            cursor += 1;
        }
        cursor += delimiter.len();
    }
}

/// Find the next `CRLF--boundary` (or `LF--boundary`) at or after `from`, and
/// return the index of the line break.
fn find_delimiter(body: &[u8], from: usize, delimiter: &[u8]) -> Option<usize> {
    let mut cursor = from;
    while let Some(index) = find(body, cursor, delimiter) {
        if index >= 2 && &body[index - 2..index] == b"\r\n" {
            return Some(index - 2);
        }
        if index >= 1 && body[index - 1] == b'\n' {
            return Some(index - 1);
        }
        // A boundary-looking sequence inside a payload that is NOT at the
        // start of a line is data (RFC 2046 §5.1.1) — keep scanning.
        cursor = index + delimiter.len();
    }
    None
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|index| index + from)
}

fn parse_part(bytes: &[u8]) -> Result<MultipartPart, String> {
    let (headers, payload) = split_headers(bytes)?;
    let content_disposition = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-disposition"))
        .map(|(_, value)| value.clone())
        .ok_or_else(|| "a multipart part is missing its Content-Disposition header".to_string())?;
    let (disposition, parameters) = parse_parameters(&content_disposition);
    if !disposition.eq_ignore_ascii_case("form-data") {
        return Err(format!(
            "multipart part disposition '{disposition}' is not supported (expected form-data)"
        ));
    }
    let name = parameters
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("name"))
        .map(|(_, value)| value.clone())
        .ok_or_else(|| "a multipart part is missing its name parameter".to_string())?;
    let filename = parameters
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("filename"))
        .map(|(_, value)| value.clone());
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.clone());
    Ok(MultipartPart {
        name,
        filename,
        content_type,
        body: payload.to_vec(),
    })
}

/// Split `headers CRLF CRLF payload`; LF-only bodies are tolerated.
fn split_headers(bytes: &[u8]) -> Result<(Vec<(String, String)>, &[u8]), String> {
    let separator = find(bytes, 0, b"\r\n\r\n")
        .map(|index| (index, 4))
        .or_else(|| find(bytes, 0, b"\n\n").map(|index| (index, 2)))
        .ok_or_else(|| "a multipart part has no header/body separator".to_string())?;
    let (header_block, payload) = bytes.split_at(separator.0);
    let payload = &payload[separator.1..];
    let header_text = std::str::from_utf8(header_block)
        .map_err(|_| "multipart part headers are not valid UTF-8".to_string())?;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_text.split('\n') {
        let line = line.trim_end_matches('\r');
        // RFC 5322 folded continuation lines are appended to the previous
        // header value (Mailgun clients never fold, but tolerance here is
        // free and avoids rejecting a legal body).
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, previous)) = headers.last_mut() {
                previous.push(' ');
                previous.push_str(line.trim());
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            if line.trim().is_empty() {
                continue;
            }
            return Err("a multipart part header is malformed".into());
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok((headers, payload))
}

/// Parse `value; name="a"; name2=b` into `(value, [(name, value)])`, honouring
/// quoted strings with backslash escapes.
fn parse_parameters(input: &str) -> (String, Vec<(String, String)>) {
    let mut segments = input.split(';');
    let value = segments.next().unwrap_or("").trim().to_string();
    let mut parameters = Vec::new();
    for segment in segments {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Some((name, raw)) = segment.split_once('=') else {
            continue;
        };
        parameters.push((name.trim().to_string(), unquote(raw.trim())));
    }
    (value, parameters)
}

fn unquote(raw: &str) -> String {
    let Some(inner) = raw.strip_prefix('"') else {
        return raw.to_string();
    };
    let mut out = String::new();
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return out,
            _ => out.push(ch),
        }
    }
    // Unterminated quoted string: keep what was read rather than refusing a
    // body whose parameters are unambiguous in practice.
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_parameter_is_extracted_from_any_position() {
        assert_eq!(
            boundary_from_content_type("multipart/form-data; boundary=abc").unwrap(),
            "abc"
        );
        assert_eq!(
            boundary_from_content_type(r#"multipart/form-data; charset=utf-8; boundary="a b""#)
                .unwrap(),
            "a b"
        );
        assert!(boundary_from_content_type("multipart/form-data").is_err());
        assert!(boundary_from_content_type("multipart/form-data; boundary=").is_err());
    }

    #[test]
    fn parses_text_and_file_parts() {
        let body = concat!(
            "--xyz\r\n",
            "Content-Disposition: form-data; name=\"from\"\r\n",
            "\r\n",
            "sender@example.com\r\n",
            "--xyz\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"a.txt\"\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "hello\r\n",
            "--xyz--\r\n"
        );
        let parts = parse_multipart(body.as_bytes(), "xyz").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "from");
        assert_eq!(parts[0].text().unwrap(), "sender@example.com");
        assert_eq!(parts[1].filename.as_deref(), Some("a.txt"));
        assert_eq!(parts[1].content_type.as_deref(), Some("text/plain"));
        assert_eq!(parts[1].body, b"hello");
    }

    #[test]
    fn boundary_lookalike_inside_payload_is_data() {
        let body = concat!(
            "--b\r\n",
            "Content-Disposition: form-data; name=\"text\"\r\n",
            "\r\n",
            "line --b not a delimiter\r\n",
            "--b--\r\n"
        );
        let parts = parse_multipart(body.as_bytes(), "b").unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].text().unwrap(), "line --b not a delimiter");
    }

    #[test]
    fn escape_sequences_in_quoted_parameters_are_decoded() {
        let body = concat!(
            "--b\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"a \\\"b\\\".txt\"\r\n",
            "\r\n",
            "x\r\n",
            "--b--\r\n"
        );
        let parts = parse_multipart(body.as_bytes(), "b").unwrap();
        assert_eq!(parts[0].filename.as_deref(), Some(r#"a "b".txt"#));
    }

    #[test]
    fn lf_only_bodies_are_accepted() {
        let body = concat!(
            "--b\n",
            "Content-Disposition: form-data; name=\"subject\"\n",
            "\n",
            "hi\n",
            "--b--\n"
        );
        let parts = parse_multipart(body.as_bytes(), "b").unwrap();
        assert_eq!(parts[0].text().unwrap(), "hi");
    }

    #[test]
    fn malformed_bodies_are_named_refusals() {
        assert!(parse_multipart(b"", "b").is_err());
        assert!(parse_multipart(b"--other\r\n\r\nx\r\n--other--", "b").is_err());
        // Missing closing delimiter.
        let unterminated = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx";
        assert!(parse_multipart(unterminated, "b").is_err());
        // Part without Content-Disposition.
        let no_disposition = b"--b\r\nX-Other: 1\r\n\r\nx\r\n--b--";
        assert!(parse_multipart(no_disposition, "b").is_err());
        // Part without a name parameter.
        let no_name = b"--b\r\nContent-Disposition: form-data\r\n\r\nx\r\n--b--";
        assert!(parse_multipart(no_name, "b").is_err());
    }

    #[test]
    fn non_utf8_field_is_a_named_refusal() {
        let mut body =
            Vec::from(&b"--b\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n"[..]);
        body.extend_from_slice(&[0xff, 0xfe]);
        body.extend_from_slice(b"\r\n--b--");
        let parts = parse_multipart(&body, "b").unwrap();
        assert!(parts[0].text().is_err());
    }
}
