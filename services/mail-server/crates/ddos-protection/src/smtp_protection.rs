//! # SMTP Protocol-Level DDoS Protection
//!
//! Implements://! - SMTP protocol state machine with strict command sequence validation
//! - Tarpit (artificial delay) for suspicious connections
//! - Slowloris detection (minimum data rate enforcement)
//! - Per-IP connection rate limiting
//! - Phase-based timeouts

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

/// SMTP connection state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpState {
    /// Just connected, waiting for greeting
    Connected,
    /// Greeting sent, waiting for EHLO/HELO
    GreetingPending,
    /// EHLO/HELO received
    GreetingReceived,
    /// MAIL FROM received
    MailFrom,
    /// RCPT TO received (with recipient count)
    RcptTo {
        /// Number of accepted RCPT TO commands in current transaction.
        count: u32,
    },
    /// DATA command received, waiting for body
    Data,
    /// Receiving message body data
    DataReceiving {
        /// Number of DATA bytes received so far for the current message.
        bytes: usize,
    },
    /// QUIT received
    Quit,
}

/// Actions the SMTP handler should take
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpAction {
    /// Continue processing normally
    Continue,
    /// Reject with given SMTP reply
    Reject(&'static str),
    /// Disconnect the client
    Disconnect,
    /// Tarpit:delay response by given duration
    Tarpit(Duration),
}

/// Parsed SMTP commands
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    /// EHLO with domain
    Ehlo(String),
    /// HELO with domain
    Helo(String),
    /// MAIL FROM with address
    MailFrom(String),
    /// RCPT TO with address
    RcptTo(String),
    /// DATA command
    Data,
    /// RSET (reset transaction)
    Rset,
    /// NOOP (no operation)
    Noop,
    /// QUIT
    Quit,
    /// VRFY (verify)
    Vrfy(String),
    /// HELP
    Help,
    /// STARTTLS
    StartTls,
    /// AUTH
    Auth(String),
    /// Unknown command
    Unknown(String),
}

/// SMTP protection configuration
#[derive(Debug, Clone)]
pub struct SmtpProtectionConfig {
    /// Max time in CONNECTED state before greeting
    pub connect_timeout: Duration,
    /// Max time waiting for any SMTP command
    pub command_timeout: Duration,
    /// Max time in DATA receiving state
    pub data_timeout: Duration,
    /// Max recipients per message
    pub max_rcpt: u32,
    /// Max message size in bytes
    pub max_size: usize,
    /// Max commands per session
    pub max_commands: u32,
    /// Max invalid/out-of-sequence commands before tarpit
    pub max_invalid: u32,
    /// Base tarpit delay per invalid command
    pub tarpit_delay: Duration,
    /// Strict mode:reject on protocol violations
    pub strict_mode: bool,
    /// Minimum data rate in bytes per second (slowloris protection)
    pub min_data_rate_bps: u64,
    /// Max concurrent connections per IP
    pub max_connections_per_ip: u32,
    /// Connection rate limit:max new connections per IP per minute
    pub conn_rate_per_minute: u32,
}

impl Default for SmtpProtectionConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(60),
            data_timeout: Duration::from_secs(300),
            max_rcpt: 100,
            max_size: 25 * 1024 * 1024, // 25MB
            max_commands: 100,
            max_invalid: 5,
            tarpit_delay: Duration::from_secs(5),
            strict_mode: true,
            min_data_rate_bps: 100, // 100 bytes per second minimum
            max_connections_per_ip: 50,
            conn_rate_per_minute: 30,
        }
    }
}

/// Per-connection SMTP protection state
pub struct SmtpConnectionProtection {
    /// Current protocol state
    state: SmtpState,
    /// Client IP
    peer_addr: IpAddr,
    /// Time the current state was entered
    state_entered_at: Instant,
    /// Total commands received in this session
    commands_received: u32,
    /// Invalid/out-of-sequence commands in this session
    invalid_commands: u32,
    /// Total bytes received (data phase)
    bytes_received: usize,
    /// Connection start time
    connected_at: Instant,
    /// Configuration
    config: SmtpProtectionConfig,
    /// Reputation score (0-100, higher is more trusted)
    reputation: u8,
}

/// SMTP protection errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpProtectionError {
    /// Too many commands in this session
    TooManyCommands,
    /// State timeout exceeded
    Timeout(SmtpState),
    /// Invalid command sequence
    InvalidSequence {
        /// Current state
        state: SmtpState,
        /// The command that was sent
        command: String,
    },
    /// Too many recipients
    TooManyRecipients,
    /// Message too large
    MessageTooLarge,
    /// Slowloris detected (data below minimum rate)
    SlowlorisDetected {
        /// Observed rate in bytes per second
        observed_rate: u64,
        /// Required minimum rate
        required_rate: u64,
    },
    /// Connection rate limit exceeded
    ConnectionRateLimited,
    /// Too many concurrent connections
    TooManyConcurrent,
}

impl std::fmt::Display for SmtpProtectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyCommands => write!(f, "Too many commands in session"),
            Self::Timeout(state) => write!(f, "Timeout in state {:?}", state),
            Self::InvalidSequence { state, command } => {
                write!(f, "Invalid command '{}' in state {:?}", command, state)
            }
            Self::TooManyRecipients => write!(f, "Too many recipients"),
            Self::MessageTooLarge => write!(f, "Message too large"),
            Self::SlowlorisDetected {
                observed_rate,
                required_rate,
            } => {
                write!(
                    f,
                    "Slowloris detected: {} bps < {} bps min",
                    observed_rate, required_rate
                )
            }
            Self::ConnectionRateLimited => write!(f, "Connection rate limited"),
            Self::TooManyConcurrent => write!(f, "Too many concurrent connections"),
        }
    }
}

impl std::error::Error for SmtpProtectionError {}

impl SmtpConnectionProtection {
    /// Create a new SMTP connection protection instance
    pub fn new(peer_addr: IpAddr, reputation: u8, config: SmtpProtectionConfig) -> Self {
        let now = Instant::now();
        Self {
            state: SmtpState::Connected,
            peer_addr,
            state_entered_at: now,
            commands_received: 0,
            invalid_commands: 0,
            bytes_received: 0,
            connected_at: now,
            config,
            reputation,
        }
    }

    /// Get the current SMTP state
    pub fn state(&self) -> SmtpState {
        self.state
    }

    /// Get number of commands received
    pub fn commands_received(&self) -> u32 {
        self.commands_received
    }

    /// Get number of invalid commands
    pub fn invalid_commands(&self) -> u32 {
        self.invalid_commands
    }

    /// Get the client IP
    pub fn peer_addr(&self) -> IpAddr {
        self.peer_addr
    }

    /// Get connection age
    pub fn connection_age(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Check if this connection should be tarpitted
    pub fn should_tarpit(&self) -> Option<Duration> {
        if self.invalid_commands > self.config.max_invalid {
            // Progressive tarpit:delay increases with each invalid command
            let multiplier = self.invalid_commands - self.config.max_invalid;
            Some(self.config.tarpit_delay * multiplier)
        } else if self.reputation < 20 {
            // Bad reputation = slower responses
            Some(Duration::from_secs(2))
        } else {
            None
        }
    }

    /// Process an SMTP command and return the appropriate action
    pub fn process_command(&mut self, raw_cmd: &str) -> Result<SmtpAction, SmtpProtectionError> {
        self.commands_received += 1;

        // Check command limits
        if self.commands_received > self.config.max_commands {
            return Err(SmtpProtectionError::TooManyCommands);
        }

        // Check state timeout
        let elapsed = self.state_entered_at.elapsed();
        let timeout = match self.state {
            SmtpState::Connected | SmtpState::GreetingPending => self.config.connect_timeout,
            SmtpState::DataReceiving { .. } => self.config.data_timeout,
            _ => self.config.command_timeout,
        };

        if elapsed > timeout {
            return Err(SmtpProtectionError::Timeout(self.state));
        }

        // Parse SMTP command
        let cmd = parse_smtp_command(raw_cmd);

        // QUIT always bypasses tarpit — releasing connections saves server resources
        if matches!(cmd, SmtpCommand::Quit) {
            self.transition(SmtpState::Quit);
            return Ok(SmtpAction::Disconnect);
        }

        // Validate command sequence (protocol state machine)
        // NOTE:We process the state machine FIRST so that record_invalid is called
        // for bad commands even when tarpitting. This ensures the tarpit delay escalates.
        let result = match (&self.state, &cmd) {
            // EHLO/HELO allowed from Connected or GreetingPending
            (SmtpState::Connected | SmtpState::GreetingPending, SmtpCommand::Ehlo(_))
            | (SmtpState::Connected | SmtpState::GreetingPending, SmtpCommand::Helo(_)) => {
                self.transition(SmtpState::GreetingReceived);
                Ok(SmtpAction::Continue)
            }

            // EHLO/HELO also allowed after greeting (re-greeting)
            (SmtpState::GreetingReceived, SmtpCommand::Ehlo(_))
            | (SmtpState::GreetingReceived, SmtpCommand::Helo(_)) => {
                self.transition(SmtpState::GreetingReceived);
                Ok(SmtpAction::Continue)
            }

            // MAIL FROM from GreetingReceived or after RSET
            (SmtpState::GreetingReceived, SmtpCommand::MailFrom(_)) => {
                self.transition(SmtpState::MailFrom);
                Ok(SmtpAction::Continue)
            }

            // RCPT TO from MailFrom or more RcptTo
            (SmtpState::MailFrom, SmtpCommand::RcptTo(_)) => {
                self.transition(SmtpState::RcptTo { count: 1 });
                Ok(SmtpAction::Continue)
            }
            (SmtpState::RcptTo { count }, SmtpCommand::RcptTo(_)) => {
                let new_count = count + 1;
                if new_count > self.config.max_rcpt {
                    return Err(SmtpProtectionError::TooManyRecipients);
                }
                self.transition(SmtpState::RcptTo { count: new_count });
                Ok(SmtpAction::Continue)
            }

            // DATA from RcptTo
            (SmtpState::RcptTo { .. }, SmtpCommand::Data) => {
                self.transition(SmtpState::DataReceiving { bytes: 0 });
                Ok(SmtpAction::Continue)
            }

            // RSET from most states -> back to GreetingReceived
            (
                SmtpState::GreetingReceived
                | SmtpState::MailFrom
                | SmtpState::RcptTo { .. }
                | SmtpState::Data
                | SmtpState::DataReceiving { .. },
                SmtpCommand::Rset,
            ) => {
                self.transition(SmtpState::GreetingReceived);
                Ok(SmtpAction::Continue)
            }

            // QUIT from any state
            (_, SmtpCommand::Quit) => {
                self.transition(SmtpState::Quit);
                Ok(SmtpAction::Disconnect)
            }

            // NOOP from any state (except Quit)
            (SmtpState::Quit, SmtpCommand::Noop) => {
                self.record_invalid();
                if self.config.strict_mode {
                    Err(SmtpProtectionError::InvalidSequence {
                        state: self.state,
                        command: raw_cmd.to_string(),
                    })
                } else {
                    Ok(SmtpAction::Reject("503 Bad sequence of commands"))
                }
            }
            (_, SmtpCommand::Noop) => Ok(SmtpAction::Continue),

            // HELP from any state
            (_, SmtpCommand::Help) => Ok(SmtpAction::Continue),

            // STARTTLS only from GreetingReceived
            (SmtpState::GreetingReceived, SmtpCommand::StartTls) => Ok(SmtpAction::Continue),

            // AUTH only from GreetingReceived
            (SmtpState::GreetingReceived, SmtpCommand::Auth(_)) => Ok(SmtpAction::Continue),

            // VRFY from GreetingReceived
            (SmtpState::GreetingReceived, SmtpCommand::Vrfy(_)) => Ok(SmtpAction::Continue),

            // Unknown commands
            (_, SmtpCommand::Unknown(_)) => {
                self.record_invalid();
                if self.config.strict_mode {
                    Err(SmtpProtectionError::InvalidSequence {
                        state: self.state,
                        command: raw_cmd.to_string(),
                    })
                } else {
                    Ok(SmtpAction::Reject("500 Unrecognized command"))
                }
            }

            // Everything else = invalid sequence
            _ => {
                self.record_invalid();
                if self.config.strict_mode {
                    Err(SmtpProtectionError::InvalidSequence {
                        state: self.state,
                        command: raw_cmd.to_string(),
                    })
                } else {
                    Ok(SmtpAction::Reject("503 Bad sequence of commands"))
                }
            }
        };

        // After processing the command through the state machine (which updates
        // invalid_commands count), check if we should tarpit. This ensures the
        // tarpit delay escalates as more invalid commands accumulate.
        if let Some(delay) = self.should_tarpit() {
            return Ok(SmtpAction::Tarpit(delay));
        }

        result
    }

    /// Record incoming data bytes (during DATA phase)
    pub fn record_data(&mut self, new_bytes: usize) -> Result<(), SmtpProtectionError> {
        if let SmtpState::DataReceiving { ref mut bytes } = self.state {
            *bytes += new_bytes;
            self.bytes_received += new_bytes;

            if *bytes > self.config.max_size {
                return Err(SmtpProtectionError::MessageTooLarge);
            }
        }
        Ok(())
    }

    /// Check data rate for slowloris detection. Returns error if rate is too low.
    /// `total_bytes` = bytes received since start of DATA phase
    /// `elapsed` = time since DATA phase started
    pub fn check_data_rate(
        &self,
        total_bytes: usize,
        elapsed: Duration,
    ) -> Result<(), SmtpProtectionError> {
        // Only check after a minimum period (1 second) to avoid false positives
        if elapsed < Duration::from_secs(1) {
            return Ok(());
        }

        // Use floating-point division for precise rate calculation.
        // Integer division (as_secs) truncates sub-second time, inflating the
        // calculated rate and letting slowloris attacks at second boundaries pass.
        let elapsed_secs = elapsed.as_secs_f64();
        let rate_bps = if elapsed_secs > 0.0 {
            let raw = total_bytes as f64 / elapsed_secs;
            if raw.is_finite() {
                raw as u64
            } else {
                0
            }
        } else {
            0
        };
        if rate_bps < self.config.min_data_rate_bps {
            return Err(SmtpProtectionError::SlowlorisDetected {
                observed_rate: rate_bps,
                required_rate: self.config.min_data_rate_bps,
            });
        }
        Ok(())
    }

    /// Transition to a new state
    fn transition(&mut self, new_state: SmtpState) {
        self.state = new_state;
        self.state_entered_at = Instant::now();
    }

    /// Record an invalid command
    fn record_invalid(&mut self) {
        self.invalid_commands += 1;
    }
}

/// Per-IP connection tracker for rate limiting
pub struct SmtpConnectionTracker {
    /// Per-IP active connection count
    active_connections: Arc<DashMap<IpAddr, AtomicU64>>,
    /// Per-IP connection timestamps for rate limiting
    connection_history: Arc<DashMap<IpAddr, RwLock<Vec<Instant>>>>,
    /// Configuration
    config: SmtpProtectionConfig,
}

impl SmtpConnectionTracker {
    /// Create a new connection tracker
    pub fn new(config: SmtpProtectionConfig) -> Self {
        Self {
            active_connections: Arc::new(DashMap::new()),
            connection_history: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Register a new connection. Returns error if limits are exceeded.
    pub fn register_connection(&self, ip: IpAddr) -> Result<(), SmtpProtectionError> {
        // Check concurrent connection limit.
        // IMPORTANT:Scope the `count` RefMut so the DashMap shard lock is released
        // before we do anything else on active_connections. Failing to do so causes
        // a deadlock if the rate-limit branch also accesses active_connections.
        {
            let count = self
                .active_connections
                .entry(ip)
                .or_insert_with(|| AtomicU64::new(0));
            let current = count.fetch_add(1, Ordering::SeqCst);

            if current >= self.config.max_connections_per_ip as u64 {
                count.fetch_sub(1, Ordering::SeqCst);
                return Err(SmtpProtectionError::TooManyConcurrent);
            }
        } // `count` (RefMut) dropped here — shard lock released

        // Check connection rate limit
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(60); // 1-minute window

        let history = self
            .connection_history
            .entry(ip)
            .or_insert_with(|| RwLock::new(Vec::new()));

        let mut times = history.write();
        // Remove old entries
        times.retain(|t| *t > cutoff);

        if times.len() >= self.config.conn_rate_per_minute as usize {
            // Undo the active count increment (safe:no conflicting lock held)
            if let Some(c) = self.active_connections.get(&ip) {
                c.fetch_sub(1, Ordering::SeqCst);
            }
            return Err(SmtpProtectionError::ConnectionRateLimited);
        }

        times.push(now);
        Ok(())
    }

    /// Unregister a closed connection
    pub fn unregister_connection(&self, ip: &IpAddr) {
        if let Some(count) = self.active_connections.get(ip) {
            // Use a CAS loop to prevent underflow past zero
            loop {
                let current = count.load(Ordering::SeqCst);
                if current == 0 {
                    // Already zero — don't decrement (would wrap to u64::MAX)
                    break;
                }
                match count.compare_exchange(
                    current,
                    current - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(prev) => {
                        if prev <= 1 {
                            // Clean up zero entries
                            drop(count);
                            self.active_connections.remove(ip);
                        }
                        break;
                    }
                    Err(_) => continue, // Value changed, retry
                }
            }
        }
    }

    /// Get active connection count for an IP
    pub fn active_count(&self, ip: &IpAddr) -> u64 {
        self.active_connections
            .get(ip)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get total tracked IPs
    pub fn tracked_ips(&self) -> usize {
        self.active_connections.len()
    }

    /// Cleanup stale entries
    pub fn cleanup(&self) {
        // Remove zero-count entries
        self.active_connections
            .retain(|_, v| v.load(Ordering::Relaxed) > 0);

        // Remove old history
        let cutoff = Instant::now() - Duration::from_secs(120);
        self.connection_history.retain(|_, v| {
            let times = v.read();
            times.iter().any(|t| *t > cutoff)
        });
    }
}

/// Parse a raw SMTP command line into a `SmtpCommand`
pub fn parse_smtp_command(raw: &str) -> SmtpCommand {
    let trimmed = raw.trim();
    let upper = trimmed.to_uppercase();

    if upper.starts_with("EHLO ") {
        SmtpCommand::Ehlo(trimmed[5..].trim().to_string())
    } else if upper.starts_with("HELO ") {
        SmtpCommand::Helo(trimmed[5..].trim().to_string())
    } else if upper.starts_with("MAIL FROM:") {
        SmtpCommand::MailFrom(trimmed[10..].trim().to_string())
    } else if upper.starts_with("RCPT TO:") {
        SmtpCommand::RcptTo(trimmed[8..].trim().to_string())
    } else if upper == "DATA" {
        SmtpCommand::Data
    } else if upper == "RSET" {
        SmtpCommand::Rset
    } else if upper == "NOOP" {
        SmtpCommand::Noop
    } else if upper == "QUIT" {
        SmtpCommand::Quit
    } else if upper.starts_with("VRFY ") {
        SmtpCommand::Vrfy(trimmed[5..].trim().to_string())
    } else if upper == "HELP" || upper.starts_with("HELP ") {
        SmtpCommand::Help
    } else if upper == "STARTTLS" {
        SmtpCommand::StartTls
    } else if upper.starts_with("AUTH ") {
        SmtpCommand::Auth(trimmed[5..].trim().to_string())
    } else {
        SmtpCommand::Unknown(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn default_config() -> SmtpProtectionConfig {
        SmtpProtectionConfig::default()
    }

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    #[test]
    fn test_parse_smtp_commands() {
        assert!(
            matches!(parse_smtp_command("EHLO example.com"), SmtpCommand::Ehlo(d) if d == "example.com")
        );
        assert!(
            matches!(parse_smtp_command("HELO example.com"), SmtpCommand::Helo(d) if d == "example.com")
        );
        assert!(
            matches!(parse_smtp_command("MAIL FROM:<user@example.com>"), SmtpCommand::MailFrom(a) if a == "<user@example.com>")
        );
        assert!(
            matches!(parse_smtp_command("RCPT TO:<dest@example.com>"), SmtpCommand::RcptTo(a) if a == "<dest@example.com>")
        );
        assert!(matches!(parse_smtp_command("DATA"), SmtpCommand::Data));
        assert!(matches!(parse_smtp_command("RSET"), SmtpCommand::Rset));
        assert!(matches!(parse_smtp_command("NOOP"), SmtpCommand::Noop));
        assert!(matches!(parse_smtp_command("QUIT"), SmtpCommand::Quit));
        assert!(matches!(
            parse_smtp_command("STARTTLS"),
            SmtpCommand::StartTls
        ));
        assert!(matches!(
            parse_smtp_command("AUTH PLAIN dGVzdA=="),
            SmtpCommand::Auth(_)
        ));
        assert!(matches!(
            parse_smtp_command("XYZZY"),
            SmtpCommand::Unknown(_)
        ));
    }

    #[test]
    fn test_case_insensitive_parsing() {
        assert!(matches!(
            parse_smtp_command("ehlo test.com"),
            SmtpCommand::Ehlo(_)
        ));
        assert!(matches!(
            parse_smtp_command("Ehlo test.com"),
            SmtpCommand::Ehlo(_)
        ));
        assert!(matches!(parse_smtp_command("quit"), SmtpCommand::Quit));
        assert!(matches!(parse_smtp_command("data"), SmtpCommand::Data));
    }

    #[test]
    fn test_valid_smtp_session() {
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, default_config());

        assert_eq!(prot.state(), SmtpState::Connected);

        let action = prot
            .process_command("EHLO example.com")
            .expect("test should succeed");
        assert_eq!(action, SmtpAction::Continue);
        assert_eq!(prot.state(), SmtpState::GreetingReceived);

        let action = prot
            .process_command("MAIL FROM:<sender@example.com>")
            .expect("test should succeed");
        assert_eq!(action, SmtpAction::Continue);
        assert_eq!(prot.state(), SmtpState::MailFrom);

        let action = prot
            .process_command("RCPT TO:<recipient@example.com>")
            .expect("test should succeed");
        assert_eq!(action, SmtpAction::Continue);
        assert!(matches!(prot.state(), SmtpState::RcptTo { count: 1 }));

        let action = prot.process_command("DATA").expect("test should succeed");
        assert_eq!(action, SmtpAction::Continue);
        assert!(matches!(prot.state(), SmtpState::DataReceiving { .. }));

        let action = prot.process_command("QUIT").expect("test should succeed");
        assert_eq!(action, SmtpAction::Disconnect);
        assert_eq!(prot.state(), SmtpState::Quit);
    }

    #[test]
    fn test_invalid_sequence_strict() {
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, default_config());
        // Try MAIL FROM before EHLO - should be invalid in strict mode
        let result = prot.process_command("MAIL FROM:<user@test.com>");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_sequence_lenient() {
        let mut config = default_config();
        config.strict_mode = false;
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, config);
        let action = prot
            .process_command("MAIL FROM:<user@test.com>")
            .expect("test should succeed");
        assert_eq!(action, SmtpAction::Reject("503 Bad sequence of commands"));
    }

    #[test]
    fn test_too_many_recipients() {
        let mut config = default_config();
        config.max_rcpt = 3;
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, config);

        prot.process_command("EHLO test.com")
            .expect("test should succeed");
        prot.process_command("MAIL FROM:<s@t.com>")
            .expect("test should succeed");
        prot.process_command("RCPT TO:<a@t.com>")
            .expect("test should succeed");
        prot.process_command("RCPT TO:<b@t.com>")
            .expect("test should succeed");
        prot.process_command("RCPT TO:<c@t.com>")
            .expect("test should succeed");
        let result = prot.process_command("RCPT TO:<d@t.com>");
        assert!(matches!(
            result,
            Err(SmtpProtectionError::TooManyRecipients)
        ));
    }

    #[test]
    fn test_too_many_commands() {
        let mut config = default_config();
        config.max_commands = 5;
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, config);

        for _i in 0..5 {
            // NOOP is always valid from Connected state (except Quit)
            let _ = prot.process_command("NOOP");
        }
        let result = prot.process_command("NOOP");
        assert!(matches!(result, Err(SmtpProtectionError::TooManyCommands)));
    }

    #[test]
    fn test_tarpit_on_bad_reputation() {
        let prot = SmtpConnectionProtection::new(test_ip(), 15, default_config());
        let delay = prot.should_tarpit();
        assert!(delay.is_some());
        assert_eq!(delay.expect("test should succeed"), Duration::from_secs(2));
    }

    #[test]
    fn test_no_tarpit_good_reputation() {
        let prot = SmtpConnectionProtection::new(test_ip(), 80, default_config());
        assert!(prot.should_tarpit().is_none());
    }

    #[test]
    fn test_progressive_tarpit_on_invalid() {
        let mut config = default_config();
        config.strict_mode = false;
        config.max_invalid = 2;
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, config);

        // Send invalid commands
        prot.process_command("XYZZY").expect("test should succeed");
        prot.process_command("GARBAGE")
            .expect("test should succeed");
        assert!(prot.should_tarpit().is_none()); // At max_invalid, not over

        prot.process_command("BOGUS").expect("test should succeed");
        let tarpit = prot.should_tarpit();
        assert!(tarpit.is_some());
        assert_eq!(tarpit.expect("test should succeed"), Duration::from_secs(5));
        // 1 * base delay
    }

    #[test]
    fn test_message_too_large() {
        let mut config = default_config();
        config.max_size = 1024;
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, config);

        prot.process_command("EHLO test.com")
            .expect("test should succeed");
        prot.process_command("MAIL FROM:<s@t.com>")
            .expect("test should succeed");
        prot.process_command("RCPT TO:<r@t.com>")
            .expect("test should succeed");
        prot.process_command("DATA").expect("test should succeed");

        prot.record_data(500).expect("test should succeed");
        prot.record_data(500).expect("test should succeed");
        let result = prot.record_data(100);
        assert!(matches!(result, Err(SmtpProtectionError::MessageTooLarge)));
    }

    #[test]
    fn test_slowloris_detection() {
        let config = default_config();
        let prot = SmtpConnectionProtection::new(test_ip(), 50, config);

        // Good rate:1000 bytes in 1 second = 1000 bps > 100 bps minimum
        assert!(prot.check_data_rate(1000, Duration::from_secs(1)).is_ok());

        // Bad rate:10 bytes in 2 seconds = 5 bps < 100 bps minimum
        let result = prot.check_data_rate(10, Duration::from_secs(2));
        assert!(matches!(
            result,
            Err(SmtpProtectionError::SlowlorisDetected { .. })
        ));
    }

    #[test]
    fn test_slowloris_grace_period() {
        let config = default_config();
        let prot = SmtpConnectionProtection::new(test_ip(), 50, config);

        // Under 1 second:grace period, no check
        assert!(prot.check_data_rate(0, Duration::from_millis(500)).is_ok());
    }

    #[test]
    fn test_rset_resets_state() {
        let mut prot = SmtpConnectionProtection::new(test_ip(), 50, default_config());
        prot.process_command("EHLO test.com")
            .expect("test should succeed");
        prot.process_command("MAIL FROM:<s@t.com>")
            .expect("test should succeed");
        prot.process_command("RSET").expect("test should succeed");
        assert_eq!(prot.state(), SmtpState::GreetingReceived);
    }

    #[test]
    fn test_connection_tracker_concurrent_limit() {
        let mut config = default_config();
        config.max_connections_per_ip = 2;
        let tracker = SmtpConnectionTracker::new(config);
        let ip = test_ip();

        tracker
            .register_connection(ip)
            .expect("test should succeed");
        tracker
            .register_connection(ip)
            .expect("test should succeed");
        let result = tracker.register_connection(ip);
        assert!(matches!(
            result,
            Err(SmtpProtectionError::TooManyConcurrent)
        ));
    }

    #[test]
    fn test_connection_tracker_unregister() {
        let mut config = default_config();
        config.max_connections_per_ip = 2;
        let tracker = SmtpConnectionTracker::new(config);
        let ip = test_ip();

        tracker
            .register_connection(ip)
            .expect("test should succeed");
        tracker
            .register_connection(ip)
            .expect("test should succeed");
        tracker.unregister_connection(&ip);
        // Should be able to register again
        tracker
            .register_connection(ip)
            .expect("test should succeed");
    }

    #[test]
    fn test_connection_tracker_active_count() {
        let tracker = SmtpConnectionTracker::new(default_config());
        let ip = test_ip();

        assert_eq!(tracker.active_count(&ip), 0);
        tracker
            .register_connection(ip)
            .expect("test should succeed");
        assert_eq!(tracker.active_count(&ip), 1);
        tracker
            .register_connection(ip)
            .expect("test should succeed");
        assert_eq!(tracker.active_count(&ip), 2);
        tracker.unregister_connection(&ip);
        assert_eq!(tracker.active_count(&ip), 1);
    }
}
