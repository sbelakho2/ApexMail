//! A tiny scriptable SMTP server for the relay tests.
//!
//! Supports exactly what the relay speaks: greeting, EHLO/HELO, STARTTLS
//! (advertisement only — a real handshake is never attempted in tests),
//! MAIL FROM, RCPT TO, DATA and QUIT. Every reply is scriptable so a test can
//! say "the first RCPT is 450, then 250".

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// One SMTP reply (code + text).
#[derive(Debug, Clone)]
pub struct ReplySpec {
    pub code: u16,
    pub text: String,
}

impl ReplySpec {
    pub fn new(code: u16, text: &str) -> Self {
        Self {
            code: code,
            text: text.to_string(),
        }
    }

    pub fn ok() -> Self {
        Self::new(250, "OK")
    }

    pub fn line(&self) -> String {
        format!("{} {}\r\n", self.code, self.text)
    }
}

/// A reply script: values are consumed in order, the last one repeats
/// forever.
#[derive(Debug, Clone)]
pub struct ScriptedReply {
    replies: Arc<Mutex<Vec<ReplySpec>>>,
    fallback: ReplySpec,
}

impl ScriptedReply {
    pub fn always(reply: ReplySpec) -> Self {
        Self {
            fallback: reply,
            replies: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn sequence(replies: Vec<ReplySpec>) -> Self {
        let fallback = replies.last().cloned().unwrap_or_else(ReplySpec::ok);
        Self {
            fallback,
            replies: Arc::new(Mutex::new(replies)),
        }
    }

    fn next(&self) -> ReplySpec {
        let mut queue = self
            .replies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if queue.is_empty() {
            self.fallback.clone()
        } else {
            queue.remove(0)
        }
    }
}

/// Fake server behaviour.
#[derive(Debug, Clone)]
pub struct FakeSmtpConfig {
    pub advertise_starttls: bool,
    pub greeting: ReplySpec,
    pub mail_from: ScriptedReply,
    pub default_rcpt: ScriptedReply,
    pub rcpt: Arc<Mutex<HashMap<String, ScriptedReply>>>,
    pub end_of_data: ScriptedReply,
}

impl Default for FakeSmtpConfig {
    fn default() -> Self {
        Self {
            advertise_starttls: false,
            greeting: ReplySpec::new(220, "fake ESMTP ready"),
            mail_from: ScriptedReply::always(ReplySpec::ok()),
            default_rcpt: ScriptedReply::always(ReplySpec::ok()),
            rcpt: Arc::new(Mutex::new(HashMap::new())),
            end_of_data: ScriptedReply::always(ReplySpec::new(250, "2.0.0 queued")),
        }
    }
}

impl FakeSmtpConfig {
    pub fn rcpt_replies(&mut self, recipient: &str, replies: Vec<ReplySpec>) {
        let mut map = self
            .rcpt
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.insert(recipient.to_string(), ScriptedReply::sequence(replies));
    }
}

/// One message the fake server received.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// Empty string = null reverse path (`MAIL FROM:<>`).
    pub mail_from: String,
    pub recipients: Vec<String>,
    /// Raw DATA payload with the terminating `<CRLF>.<CRLF>` stripped.
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
struct ServerState {
    connections: usize,
    commands: Vec<String>,
    messages: Vec<ReceivedMessage>,
}

/// Running fake server; shuts down when dropped.
pub struct FakeSmtpServer {
    addr: SocketAddr,
    state: Arc<Mutex<ServerState>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeSmtpServer {
    pub async fn start(config: FakeSmtpConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake SMTP listener");
        let addr = listener.local_addr().expect("fake listener addr");
        let state = Arc::new(Mutex::new(ServerState::default()));
        let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else { break };
                        task_state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .connections += 1;
                        let config = config.clone();
                        let state = Arc::clone(&task_state);
                        tokio::spawn(async move {
                            let _ = handle_connection(stream, config, state).await;
                        });
                    }
                }
            }
        });
        Self {
            addr,
            state,
            shutdown: Some(shutdown),
            task,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn connections(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connections
    }

    pub fn commands(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .commands
            .clone()
    }

    pub fn messages(&self) -> Vec<ReceivedMessage> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .messages
            .clone()
    }
}

impl Drop for FakeSmtpServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    config: FakeSmtpConfig,
    state: Arc<Mutex<ServerState>>,
) -> std::io::Result<()> {
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    writer.write_all(config.greeting.line().as_bytes()).await?;

    let mut mail_from: Option<String> = None;
    let mut recipients: Vec<String> = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            break;
        }
        let command = line.trim_end_matches(['\r', '\n']).to_string();
        let upper = command.to_ascii_uppercase();
        state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .commands
            .push(command.clone());

        if upper.starts_with("EHLO") {
            let mut response = String::from("250-fake greets you\r\n");
            if config.advertise_starttls {
                response.push_str("250-STARTTLS\r\n");
            }
            response.push_str("250-SIZE 10485760\r\n");
            response.push_str("250 8BITMIME\r\n");
            writer.write_all(response.as_bytes()).await?;
        } else if upper.starts_with("HELO") {
            writer.write_all(b"250 fake\r\n").await?;
        } else if upper.starts_with("STARTTLS") {
            writer.write_all(b"454 4.7.0 TLS not available\r\n").await?;
        } else if upper.starts_with("MAIL FROM:") {
            mail_from = Some(extract_address(&command));
            writer
                .write_all(config.mail_from.next().line().as_bytes())
                .await?;
        } else if upper.starts_with("RCPT TO:") {
            let recipient = extract_address(&command);
            let reply = {
                let map = config
                    .rcpt
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                map.get(&recipient)
                    .cloned()
                    .unwrap_or_else(|| config.default_rcpt.clone())
            }
            .next();
            if (200..300).contains(&reply.code) {
                recipients.push(recipient);
            }
            writer.write_all(reply.line().as_bytes()).await?;
        } else if upper == "DATA" {
            writer.write_all(b"354 go ahead\r\n").await?;
            let mut data: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let read = reader.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..read]);
                if let Some(position) = find_terminator(&data) {
                    data.truncate(position + 2);
                    break;
                }
            }
            let final_reply = config.end_of_data.next();
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .messages
                .push(ReceivedMessage {
                    mail_from: mail_from.take().unwrap_or_default(),
                    recipients: std::mem::take(&mut recipients),
                    data,
                });
            writer.write_all(final_reply.line().as_bytes()).await?;
        } else if upper == "QUIT" {
            writer.write_all(b"221 bye\r\n").await?;
            break;
        } else if upper == "RSET" {
            mail_from = None;
            recipients.clear();
            writer.write_all(b"250 OK\r\n").await?;
        } else if upper == "NOOP" {
            writer.write_all(b"250 OK\r\n").await?;
        } else {
            writer
                .write_all(b"500 5.5.1 unrecognized command\r\n")
                .await?;
        }
    }
    Ok(())
}

/// Extract the address from `MAIL FROM:<x>` / `RCPT TO:<x>` (tolerates
/// parameters after the closing bracket).
fn extract_address(command: &str) -> String {
    let after_colon = command.split_once(':').map(|(_, rest)| rest).unwrap_or("");
    match (after_colon.find('<'), after_colon.find('>')) {
        (Some(open), Some(close)) if close > open => {
            after_colon[open + 1..close].trim().to_string()
        }
        _ => after_colon.trim().to_string(),
    }
}

fn find_terminator(data: &[u8]) -> Option<usize> {
    data.windows(5).position(|window| window == b"\r\n.\r\n")
}
