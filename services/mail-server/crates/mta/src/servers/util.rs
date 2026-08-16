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
pub(crate) enum LineRead {
    /// A full line (including trailing `\r\n`).
    Line(String),
    /// The line exceeded the cap; the terminator was still drained.
    TooLong,
    /// End of stream.
    Eof,
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
        Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()))
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
        assert_eq!(extract_addr_safe("RCPT TO:<a@b.com> SIZE=1000"), Some("a@b.com"));
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
}
