//! Minimal SMTP client session for recipient-facing delivery.
//!
//! One [`SmtpClient`] is one TCP connection: greeting, `EHLO` (with `HELO`
//! fallback), optional `STARTTLS` upgrade, `MAIL FROM`, `RCPT TO`, `DATA`.
//! It deliberately does not interpret policy — the relay classifies replies
//! via [`crate::response`] and decides retries/refusals.
//!
//! TLS upgrade consumes `self` (the stream type changes from plain TCP to a
//! rustls stream), which makes it impossible to accidentally keep using the
//! cleartext stream after STARTTLS.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::response::{SmtpReply, SmtpStage};
use crate::source_ip::{connect_bound, ConnectError};
use crate::tls::{connect_tls, TlsError, TlsPolicy};

/// Per-phase timeouts for an SMTP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtpTimeouts {
    /// TCP connect timeout.
    pub connect: Duration,
    /// Command/reply timeout (also used for the TLS handshake).
    pub command: Duration,
    /// Whole-message DATA write timeout.
    pub data: Duration,
}

impl Default for SmtpTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            command: Duration::from_secs(60),
            data: Duration::from_secs(600),
        }
    }
}

/// EHLO capabilities relevant to outbound delivery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EhloCapabilities {
    /// Peer advertises STARTTLS.
    pub starttls: bool,
    /// Peer's declared maximum message size, when advertised.
    pub size: Option<u64>,
    pub eight_bit_mime: bool,
}

/// SMTP session failure.
#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("SMTP I/O error during {stage}: {message}")]
    Io { stage: SmtpStage, message: String },
    #[error("SMTP read timed out during {stage}")]
    Timeout { stage: SmtpStage },
    #[error("unexpected SMTP reply at {stage}: {} {}", reply.code, reply.text)]
    Reply { stage: SmtpStage, reply: SmtpReply },
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("SMTP protocol error: {0}")]
    Protocol(String),
    #[error("the stream has already been consumed by a TLS upgrade or teardown")]
    StreamTaken,
}

impl SmtpError {
    /// When the failure is an SMTP reply, return its stage and reply so the
    /// caller can classify it.
    pub fn reply(&self) -> Option<(SmtpStage, &SmtpReply)> {
        match self {
            Self::Reply { stage, reply } => Some((*stage, reply)),
            _ => None,
        }
    }
}

/// Maximum bytes accepted for a single SMTP reply (loop protection).
const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// The plain/TLS stream duality.
enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Stream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// One SMTP client connection.
pub struct SmtpClient {
    stream: Option<Stream>,
    read_buf: Vec<u8>,
    read_pos: usize,
    timeouts: SmtpTimeouts,
    peer: String,
    actual_source_ip: Option<IpAddr>,
    capabilities: EhloCapabilities,
}

impl SmtpClient {
    /// Connect (optionally from `requested_source_ip`), complete the implicit
    /// TLS handshake when the policy requires it, and consume the greeting.
    /// A non-2xx greeting is an error carrying the reply.
    pub async fn connect(
        remote: SocketAddr,
        peer_name: &str,
        requested_source_ip: Option<IpAddr>,
        policy: TlsPolicy,
        timeouts: SmtpTimeouts,
    ) -> Result<Self, SmtpError> {
        let (tcp, actual_source_ip) =
            connect_bound(remote, requested_source_ip, timeouts.connect).await?;
        let stream = match policy {
            TlsPolicy::ImplicitTlsRequired => {
                Stream::Tls(Box::new(connect_tls(tcp, peer_name).await?))
            }
            TlsPolicy::Opportunistic | TlsPolicy::StartTlsRequired => Stream::Plain(tcp),
        };
        let mut client = Self {
            stream: Some(stream),
            read_buf: Vec::new(),
            read_pos: 0,
            timeouts,
            peer: peer_name.to_string(),
            actual_source_ip,
            capabilities: EhloCapabilities::default(),
        };
        let greeting = client.read_reply(SmtpStage::Greeting).await?;
        if !greeting.is_positive() {
            return Err(SmtpError::Reply {
                stage: SmtpStage::Greeting,
                reply: greeting,
            });
        }
        Ok(client)
    }

    /// The verified local IP of this connection (see
    /// [`crate::source_ip::connect_bound`]).
    pub fn actual_source_ip(&self) -> Option<IpAddr> {
        self.actual_source_ip
    }

    /// The MX hostname this session was opened to.
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// The capabilities from the last EHLO.
    pub fn capabilities(&self) -> &EhloCapabilities {
        &self.capabilities
    }

    /// Send EHLO; on a 5xx fall back to HELO once (RFC 5321 §4.1.1.1).
    pub async fn ehlo(&mut self, helo_domain: &str) -> Result<EhloCapabilities, SmtpError> {
        let reply = self
            .send_command(&format!("EHLO {helo_domain}"), SmtpStage::Ehlo)
            .await?;
        if reply.is_positive() {
            let capabilities = parse_capabilities(&reply);
            self.capabilities = capabilities.clone();
            return Ok(capabilities);
        }
        if reply.is_permanent() {
            let helo = self
                .send_command(&format!("HELO {helo_domain}"), SmtpStage::Ehlo)
                .await?;
            if !helo.is_positive() {
                return Err(SmtpError::Reply {
                    stage: SmtpStage::Ehlo,
                    reply: helo,
                });
            }
            self.capabilities = EhloCapabilities::default();
            return Ok(EhloCapabilities::default());
        }
        Err(SmtpError::Reply {
            stage: SmtpStage::Ehlo,
            reply,
        })
    }

    /// Upgrade this session to TLS via STARTTLS. Consumes `self` and returns
    /// the upgraded session, so the cleartext stream cannot be used again.
    pub async fn starttls(mut self, server_name: &str) -> Result<Self, SmtpError> {
        let reply = self.send_command("STARTTLS", SmtpStage::StartTls).await?;
        if !reply.is_positive() {
            return Err(SmtpError::Reply {
                stage: SmtpStage::StartTls,
                reply,
            });
        }
        let stream = self.stream.take().ok_or(SmtpError::StreamTaken)?;
        let tcp = match stream {
            Stream::Plain(tcp) => tcp,
            Stream::Tls(_) => {
                return Err(SmtpError::Protocol(
                    "STARTTLS requested on an already-encrypted stream".to_string(),
                ))
            }
        };
        let tls = connect_tls(tcp, server_name).await?;
        self.stream = Some(Stream::Tls(Box::new(tls)));
        self.read_buf.clear();
        self.read_pos = 0;
        // RFC 3207: the client MUST discard the EHLO state after STARTTLS;
        // the caller must EHLO again.
        self.capabilities = EhloCapabilities::default();
        Ok(self)
    }

    /// Send `MAIL FROM`. `from = None` means the null reverse path
    /// (`MAIL FROM:<>`, used for DSNs).
    pub async fn mail_from(&mut self, from: Option<&str>) -> Result<SmtpReply, SmtpError> {
        let address = from.map(trim_angle_brackets).unwrap_or("");
        self.send_command(&format!("MAIL FROM:<{address}>"), SmtpStage::MailFrom)
            .await
    }

    /// Send `RCPT TO`.
    pub async fn rcpt_to(&mut self, recipient: &str) -> Result<SmtpReply, SmtpError> {
        self.send_command(
            &format!("RCPT TO:<{}>", trim_angle_brackets(recipient)),
            SmtpStage::RcptTo,
        )
        .await
    }

    /// Perform the DATA exchange. Returns the FINAL reply (post-DATA 250 when
    /// accepted). If the peer refuses the DATA command itself, that reply is
    /// returned instead — the caller classifies it the same way (4xx
    /// transient, 5xx whole-message permanent).
    pub async fn data(&mut self, message: &[u8]) -> Result<SmtpReply, SmtpError> {
        let reply = self.send_command("DATA", SmtpStage::Data).await?;
        if !reply.is_intermediate() {
            return Ok(reply);
        }
        let payload = build_data_payload(message);
        let timeout = self.timeouts.data;
        {
            let stream = self.stream.as_mut().ok_or(SmtpError::StreamTaken)?;
            match tokio::time::timeout(timeout, stream.write_all(&payload)).await {
                Err(_) => {
                    return Err(SmtpError::Timeout {
                        stage: SmtpStage::EndOfData,
                    })
                }
                Ok(Err(error)) => {
                    return Err(SmtpError::Io {
                        stage: SmtpStage::EndOfData,
                        message: error.to_string(),
                    })
                }
                Ok(Ok(())) => {}
            }
            match tokio::time::timeout(timeout, stream.flush()).await {
                Err(_) => {
                    return Err(SmtpError::Timeout {
                        stage: SmtpStage::EndOfData,
                    })
                }
                Ok(Err(error)) => {
                    return Err(SmtpError::Io {
                        stage: SmtpStage::EndOfData,
                        message: error.to_string(),
                    })
                }
                Ok(Ok(())) => {}
            }
        }
        self.read_reply(SmtpStage::EndOfData).await
    }

    /// Best-effort QUIT; connection errors are ignored by the caller.
    pub async fn quit(mut self) {
        if self.stream.is_some() {
            match self.send_command("QUIT", SmtpStage::Greeting).await {
                Ok(_) => {}
                Err(error) => {
                    tracing::debug!(peer = %self.peer, error = %error, "QUIT failed; dropping connection");
                }
            }
        }
    }

    async fn send_command(
        &mut self,
        command: &str,
        stage: SmtpStage,
    ) -> Result<SmtpReply, SmtpError> {
        let line = format!("{command}\r\n");
        let timeout = self.timeouts.command;
        {
            let stream = self.stream.as_mut().ok_or(SmtpError::StreamTaken)?;
            match tokio::time::timeout(timeout, stream.write_all(line.as_bytes())).await {
                Err(_) => return Err(SmtpError::Timeout { stage }),
                Ok(Err(error)) => {
                    return Err(SmtpError::Io {
                        stage,
                        message: error.to_string(),
                    })
                }
                Ok(Ok(())) => {}
            }
            match tokio::time::timeout(timeout, stream.flush()).await {
                Err(_) => return Err(SmtpError::Timeout { stage }),
                Ok(Err(error)) => {
                    return Err(SmtpError::Io {
                        stage,
                        message: error.to_string(),
                    })
                }
                Ok(Ok(())) => {}
            }
        }
        self.read_reply(stage).await
    }

    async fn read_reply(&mut self, stage: SmtpStage) -> Result<SmtpReply, SmtpError> {
        let mut lines: Vec<String> = Vec::new();
        loop {
            let line = self.read_line(stage).await?;
            let continues = line.len() >= 4 && line.as_bytes().get(3) == Some(&b'-');
            lines.push(line);
            if !continues {
                break;
            }
            if lines.len() > 1000 {
                return Err(SmtpError::Protocol(
                    "SMTP reply exceeded 1000 lines".to_string(),
                ));
            }
        }
        SmtpReply::parse_multiline(&lines).ok_or_else(|| {
            SmtpError::Protocol(format!("unparseable SMTP reply: {}", lines.join(" | ")))
        })
    }

    async fn read_line(&mut self, stage: SmtpStage) -> Result<String, SmtpError> {
        let timeout = self.timeouts.command;
        loop {
            if let Some(offset) = self.read_buf[self.read_pos..]
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let end = self.read_pos + offset;
                let line_end = if end > self.read_pos && self.read_buf[end - 1] == b'\r' {
                    end - 1
                } else {
                    end
                };
                let line =
                    String::from_utf8_lossy(&self.read_buf[self.read_pos..line_end]).into_owned();
                self.read_pos = end + 1;
                if self.read_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                } else if self.read_pos > 8192 {
                    self.read_buf.drain(..self.read_pos);
                    self.read_pos = 0;
                }
                return Ok(line);
            }
            let stream = self.stream.as_mut().ok_or(SmtpError::StreamTaken)?;
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(timeout, stream.read(&mut chunk)).await {
                Err(_) => return Err(SmtpError::Timeout { stage }),
                Ok(Err(error)) => {
                    return Err(SmtpError::Io {
                        stage,
                        message: error.to_string(),
                    })
                }
                Ok(Ok(0)) => {
                    return Err(SmtpError::Io {
                        stage,
                        message: "connection closed by peer".to_string(),
                    })
                }
                Ok(Ok(read)) => {
                    self.read_buf.extend_from_slice(&chunk[..read]);
                    if self.read_buf.len() > MAX_REPLY_BYTES {
                        return Err(SmtpError::Protocol(
                            "SMTP reply exceeded the maximum buffer size".to_string(),
                        ));
                    }
                }
            }
        }
    }
}

/// Parse EHLO capability lines.
fn parse_capabilities(reply: &SmtpReply) -> EhloCapabilities {
    let mut capabilities = EhloCapabilities::default();
    for line in &reply.lines {
        let upper = line.trim().to_ascii_uppercase();
        if upper == "STARTTLS" || upper.starts_with("STARTTLS ") {
            capabilities.starttls = true;
        } else if let Some(rest) = upper.strip_prefix("SIZE") {
            capabilities.size = rest.trim().parse::<u64>().ok();
            if rest.trim().is_empty() {
                capabilities.size = Some(0);
            }
        } else if upper == "8BITMIME" {
            capabilities.eight_bit_mime = true;
        }
    }
    capabilities
}

fn trim_angle_brackets(address: &str) -> &str {
    address.trim().trim_matches(|c| c == '<' || c == '>')
}

/// Build the DATA payload: CRLF-normalized, dot-stuffed, terminated with
/// `<CRLF>.<CRLF>`.
pub fn build_data_payload(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 8);
    let mut index = 0usize;
    let mut at_line_start = true;
    while index < message.len() {
        let byte = message[index];
        if at_line_start && byte == b'.' {
            out.push(b'.'); // dot-stuffing (RFC 5321 §4.5.2)
        }
        match byte {
            b'\r' => {
                out.extend_from_slice(b"\r\n");
                if message.get(index + 1) == Some(&b'\n') {
                    index += 2;
                } else {
                    index += 1;
                }
                at_line_start = true;
            }
            b'\n' => {
                out.extend_from_slice(b"\r\n");
                index += 1;
                at_line_start = true;
            }
            _ => {
                out.push(byte);
                index += 1;
                at_line_start = false;
            }
        }
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_normalizes_crlf_and_terminates() {
        let payload = build_data_payload(b"Subject: hi\n\nbody");
        assert_eq!(payload, b"Subject: hi\r\n\r\nbody\r\n.\r\n");
    }

    #[test]
    fn payload_dot_stuffs_line_starts() {
        let payload = build_data_payload(b".\r\n..hidden\r\nnormal.\r\n");
        assert_eq!(payload, b"..\r\n...hidden\r\nnormal.\r\n.\r\n".to_vec());
    }

    #[test]
    fn payload_handles_bare_carriage_return() {
        let payload = build_data_payload(b"a\rb");
        assert_eq!(payload, b"a\r\nb\r\n.\r\n");
    }

    #[test]
    fn capabilities_are_parsed_from_multiline_ehlo() {
        let reply = SmtpReply::parse_multiline(&[
            "250-fake greets you".to_string(),
            "250-STARTTLS".to_string(),
            "250-SIZE 10485760".to_string(),
            "250 8BITMIME".to_string(),
        ])
        .expect("reply");
        let capabilities = parse_capabilities(&reply);
        assert!(capabilities.starttls);
        assert_eq!(capabilities.size, Some(10_485_760));
        assert!(capabilities.eight_bit_mime);
    }

    #[test]
    fn angle_brackets_are_trimmed() {
        assert_eq!(trim_angle_brackets("<a@b.c>"), "a@b.c");
        assert_eq!(trim_angle_brackets(" a@b.c "), "a@b.c");
    }
}
