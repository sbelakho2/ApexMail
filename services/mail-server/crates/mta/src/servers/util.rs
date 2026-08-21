//! Shared utilities for the SMTP servers: panic-safe address extraction,
//! line-length caps, and capped line reads.
//!
//! Every server (inbound, bounce, feedback loop, submission) reads commands
//! and DATA with the same primitives so that a hostile or buggy client can
//! neither panic a session task (`extract_addr_safe`) nor exhaust memory
//! with an unbounded line (`read_line_capped`).

use tokio::io::{AsyncRead, AsyncWrite, BufStream};

/// Maximum length of a single SMTP command line (RFC 5321 §4.5.3.1.4 limits
/// commands to 512 octets and lines to 1000; 4096 gives headroom for the
/// inline `AUTH PLAIN <base64>` payload while still bounding memory).
pub(crate) const MAX_COMMAND_LINE: usize = 4096;

/// Maximum length of a single DATA body line. RFC 5321 §4.5.3.1.6 requires
/// accepting lines of at least 1000 octets; 1 MiB per line bounds per-line
/// memory while the cumulative `max_message_size` cap is still enforced by
/// each server as the body is assembled.
pub(crate) const MAX_DATA_LINE: usize = 1024 * 1024;

/// After an over-long line, keep draining this many bytes looking for the
/// terminator so the session can resynchronise instead of closing.
pub(crate) const MAX_LINE_DRAIN: usize = 64 * 1024;

/// Extract the bare address from an SMTP command line such as
/// `RCPT TO:<user@example.com>` or `MAIL FROM: user@example.com`.
///
/// The closing `>` is always searched AFTER the opening `<` — searching the
/// whole line can find a `>` that precedes the `<` and slice out of bounds
/// (a remote panic). Returns `None` when no `<...>` path is present.
pub(crate) fn extract_addr_safe(line: &str) -> Option<&str> {
    let start = line.find('<')?;
    let end = start + 1 + line[start + 1..].find('>')?;
    Some(&line[start + 1..end])
}

/// Result of a capped line read.
#[derive(Debug)]
pub(crate) enum LineRead {
    /// A full line (including its trailing terminator), plus how the line was
    /// terminated. Callers deciding SMTP end-of-data MUST check the
    /// terminator: a line terminated by a bare LF is body data, not a
    /// `<CRLF>.<CRLF>` end-of-data marker (RFC 5321 strict mode; prevents
    /// SMTP smuggling).
    Line(String, LineTerminator),
    /// The line exceeded the cap; the terminator was still drained.
    TooLong,
    /// End of stream.
    Eof,
}

/// How a read line was terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineTerminator {
    /// Terminated by `<CRLF>` (RFC 5321 compliant).
    CrLf,
    /// Terminated by a bare `<LF>` — accepted for tolerance on command
    /// lines, but NEVER sufficient to terminate DATA.
    BareLf,
    /// The stream ended before any terminator arrived (partial line).
    Unterminated,
}

/// Strip the line's actual terminator, returning `(content, terminator)`.
pub(crate) fn split_line_terminator(line: &str) -> (&str, LineTerminator) {
    if let Some(content) = line.strip_suffix("\r\n") {
        (content, LineTerminator::CrLf)
    } else if let Some(content) = line.strip_suffix('\n') {
        (content, LineTerminator::BareLf)
    } else {
        (line, LineTerminator::Unterminated)
    }
}

/// Strip the terminator reported by `read_line_capped` (the authoritative
/// tag observed while reading — no re-derivation from the bytes).
pub(crate) fn line_content(line: &str, terminator: LineTerminator) -> &str {
    match terminator {
        LineTerminator::CrLf => line.strip_suffix("\r\n").unwrap_or(line),
        LineTerminator::BareLf => line.strip_suffix('\n').unwrap_or(line),
        LineTerminator::Unterminated => line,
    }
}

/// RFC 5321 §4.1.1.5 strict end-of-data: the line must be exactly
/// `".\r\n"` — a single dot terminated by CRLF. A bare-LF `".\n"`, a
/// space-padded `" ."`/`". "` line, or any other content is ordinary body
/// data and must NOT terminate DATA (SMTP smuggling defence).
pub(crate) fn is_strict_end_of_data(line: &str, terminator: LineTerminator) -> bool {
    terminator == LineTerminator::CrLf && line == ".\r\n"
}

/// RFC 5321 §4.5.2 dot-unstuffing: a compliant sender doubles the leading dot
/// of every body line that starts with one; the receiver therefore removes
/// exactly ONE leading dot from any body line starting with `.`. (Stripping
/// two dots — or only unstuffing `".."` — corrupts `".foo"` round-trips.)
pub(crate) fn unstuff_dot_line(content: &str) -> &str {
    content.strip_prefix('.').unwrap_or(content)
}

/// Read one line with a hard cap on its length. When the cap is exceeded,
/// the remainder of the line is drained (up to `MAX_LINE_DRAIN` bytes) so
/// the session can stay synchronised, then `LineRead::TooLong` is returned.
pub(crate) async fn read_line_capped<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    cap: usize,
) -> std::io::Result<LineRead> {
    use tokio::io::AsyncBufReadExt;
    let mut line = Vec::with_capacity(128);
    let mut too_long = false;
    let mut drained = 0usize;
    loop {
        // Scope the borrow so `buf` is dropped before `stream.consume`.
        let action = {
            let buf = stream.fill_buf().await?;
            if buf.is_empty() {
                if line.is_empty() && !too_long {
                    return Ok(LineRead::Eof);
                }
                // EOF mid-line: return what we have.
                Action::Done
            } else if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let take = pos + 1;
                if line.len() + take > cap {
                    too_long = true;
                    line.clear();
                } else if !too_long {
                    line.extend_from_slice(&buf[..take]);
                }
                // A newline-terminated line is complete — return now.
                // (Action::Return breaks after consuming; looping back to
                // fill_buf() would block until MORE data arrives, hanging
                // the session while the client waits for a reply.)
                Action::Return(take)
            } else if too_long {
                drained += buf.len();
                if drained > MAX_LINE_DRAIN {
                    Action::GiveUp
                } else {
                    Action::Consume(buf.len())
                }
            } else if line.len() + buf.len() > cap {
                too_long = true;
                line.clear();
                Action::Consume(buf.len())
            } else {
                line.extend_from_slice(buf);
                Action::Consume(buf.len())
            }
        };
        match action {
            Action::Done => break,
            Action::Return(n) => {
                stream.consume(n);
                break;
            }
            Action::GiveUp => return Ok(LineRead::TooLong),
            Action::Consume(n) => stream.consume(n),
        }
    }
    if too_long {
        Ok(LineRead::TooLong)
    } else {
        let text = String::from_utf8_lossy(&line).into_owned();
        let (_, terminator) = split_line_terminator(&text);
        Ok(LineRead::Line(text, terminator))
    }
}

enum Action {
    Done,
    Return(usize),
    Consume(usize),
    GiveUp,
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_addr_safe_basic() {
        assert_eq!(
            extract_addr_safe("MAIL FROM:<user@example.com>"),
            Some("user@example.com")
        );
        assert_eq!(
            extract_addr_safe("RCPT TO:<a@b.com> SIZE=1000"),
            Some("a@b.com")
        );
    }

    #[test]
    fn test_extract_addr_safe_empty_sender() {
        assert_eq!(extract_addr_safe("MAIL FROM:<>"), Some(""));
    }

    #[test]
    fn test_extract_addr_safe_closing_bracket_before_opening() {
        // A '>' before the '<' must not produce an out-of-range slice —
        // this exact input used to panic the session task.
        assert_eq!(
            extract_addr_safe("MAIL FROM:x> <user@example.com>"),
            Some("user@example.com")
        );
        // Unterminated path: no '>' after the '<'.
        assert_eq!(extract_addr_safe("MAIL FROM:<user@example.com"), None);
        assert_eq!(extract_addr_safe("MAIL FROM: user@example.com"), None);
    }

    // ── SMTP smuggling: strict terminator handling ──────────────────────────

    #[test]
    fn strict_end_of_data_requires_exactly_dot_crlf() {
        use LineTerminator::*;
        assert!(
            is_strict_end_of_data(".\r\n", CrLf),
            "CRLF dot terminates DATA"
        );
        assert!(!is_strict_end_of_data(".\n", BareLf), "bare-LF dot is body data");
        assert!(!is_strict_end_of_data(".\r", Unterminated), "lone CR is not a terminator");
        assert!(!is_strict_end_of_data(".", Unterminated), "unterminated dot is body data");
        // A CRLF-terminated tag with non-dot content is body data.
        assert!(!is_strict_end_of_data(".\n", CrLf), "tag and bytes disagree → body");
    }

    #[test]
    fn strict_end_of_data_rejects_padded_and_prefixed_dots() {
        use LineTerminator::*;
        // " ." / ". " / " . " must remain ordinary body lines — a trim()-based
        // check used to terminate DATA on them (smuggling vector).
        assert!(!is_strict_end_of_data(" .\r\n", CrLf));
        assert!(!is_strict_end_of_data(". \r\n", CrLf));
        assert!(!is_strict_end_of_data(" . \r\n", CrLf));
        assert!(!is_strict_end_of_data("..\r\n", CrLf), "stuffed dot is body data");
        assert!(!is_strict_end_of_data("x.\r\n", CrLf));
        assert!(!is_strict_end_of_data(".x\r\n", CrLf));
        assert!(!is_strict_end_of_data("\r\n", CrLf), "empty line is body data");
    }

    #[test]
    fn split_line_terminator_classifies_actual_terminators() {
        assert_eq!(
            split_line_terminator("DATA\r\n"),
            ("DATA", LineTerminator::CrLf)
        );
        assert_eq!(
            split_line_terminator("DATA\n"),
            ("DATA", LineTerminator::BareLf)
        );
        assert_eq!(
            split_line_terminator("DATA"),
            ("DATA", LineTerminator::Unterminated)
        );
        // A bare LF preceded by a CR that belongs to the content is not CRLF.
        assert_eq!(
            split_line_terminator("DATA\r\r\n"),
            ("DATA\r", LineTerminator::CrLf)
        );
    }

    #[test]
    fn line_content_uses_the_reported_tag() {
        use LineTerminator::*;
        assert_eq!(line_content("dot\r\n", CrLf), "dot");
        assert_eq!(line_content("dot\n", BareLf), "dot");
        assert_eq!(line_content("partial", Unterminated), "partial");
    }

    #[test]
    fn unstuff_dot_line_strips_exactly_one_leading_dot() {
        // RFC 5321 §4.5.2 round-trip: "..foo" (stuffed) → ".foo".
        assert_eq!(unstuff_dot_line("..foo"), ".foo");
        // ".." (stuffed single dot) → ".".
        assert_eq!(unstuff_dot_line(".."), ".");
        // A single unstuffed leading dot is stripped too — the receiver
        // cannot distinguish, and stripping two dots would corrupt ".foo".
        assert_eq!(unstuff_dot_line(".foo"), "foo");
        assert_eq!(unstuff_dot_line("foo"), "foo");
        assert_eq!(unstuff_dot_line(""), "");
        // Multibyte safety: '.' is one-byte ASCII, so [1..] stays on a char
        // boundary.
        assert_eq!(unstuff_dot_line(".ö-umlaut"), "ö-umlaut");
    }

    #[tokio::test]
    async fn read_line_capped_reports_the_actual_terminator() {
        let (client, server) = tokio::io::duplex(256);
        let mut writer = client;
        let mut stream = BufStream::new(server);
        tokio::io::AsyncWriteExt::write_all(&mut writer, b"one\r\ntwo\nthree")
            .await
            .unwrap();

        match read_line_capped(&mut stream, 128).await.unwrap() {
            LineRead::Line(l, t) => {
                assert_eq!(l, "one\r\n");
                assert_eq!(t, LineTerminator::CrLf);
            }
            other => panic!("expected Line, got {other:?}"),
        }
        match read_line_capped(&mut stream, 128).await.unwrap() {
            LineRead::Line(l, t) => {
                assert_eq!(l, "two\n");
                assert_eq!(t, LineTerminator::BareLf);
            }
            other => panic!("expected Line, got {other:?}"),
        }
        // Partial line then EOF: content without a terminator.
        drop(writer); // close so the read observes EOF after "three"
        match read_line_capped(&mut stream, 128).await.unwrap() {
            LineRead::Line(l, t) => {
                assert_eq!(l, "three");
                assert_eq!(t, LineTerminator::Unterminated);
            }
            other => panic!("expected Line, got {other:?}"),
        }
    }
}
