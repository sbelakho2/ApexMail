//! HTTP/2 fingerprinting implementation
//!
//! HTTP/2 fingerprints based on SETTINGS frame values, frame ordering,
//! and priority tree structure.

use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// HTTP/2 Settings identifiers
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Http2Setting {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1)
    HeaderTableSize,
    /// SETTINGS_ENABLE_PUSH (0x2)
    EnablePush,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
    MaxConcurrentStreams,
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4)
    InitialWindowSize,
    /// SETTINGS_MAX_FRAME_SIZE (0x5)
    MaxFrameSize,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
    MaxHeaderListSize,
    /// Unknown setting
    Unknown(u16),
}

#[allow(dead_code)]
impl Http2Setting {
    /// Parse from raw setting ID
    pub fn from_id(id: u16) -> Self {
        match id {
            0x1 => Self::HeaderTableSize,
            0x2 => Self::EnablePush,
            0x3 => Self::MaxConcurrentStreams,
            0x4 => Self::InitialWindowSize,
            0x5 => Self::MaxFrameSize,
            0x6 => Self::MaxHeaderListSize,
            id => Self::Unknown(id),
        }
    }
    
    /// Get raw setting ID
    pub fn to_id(&self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
            Self::Unknown(id) => *id,
        }
    }
}

/// HTTP/2 frame types observed
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FrameType {
    /// DATA frame (0x0)
    Data,
    /// HEADERS frame (0x1)
    Headers,
    /// PRIORITY frame (0x2)
    Priority,
    /// RST_STREAM frame (0x3)
    RstStream,
    /// SETTINGS frame (0x4)
    Settings,
    /// PUSH_PROMISE frame (0x5)
    PushPromise,
    /// PING frame (0x6)
    Ping,
    /// GOAWAY frame (0x7)
    GoAway,
    /// WINDOW_UPDATE frame (0x8)
    WindowUpdate,
    /// CONTINUATION frame (0x9)
    Continuation,
    /// Unknown frame type
    Unknown(u8),
}

impl FrameType {
    /// Parse from raw frame type
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            b => Self::Unknown(b),
        }
    }
    
    /// Get single-character representation
    pub fn to_char(&self) -> char {
        match self {
            Self::Data => 'd',
            Self::Headers => 'h',
            Self::Priority => 'p',
            Self::RstStream => 'r',
            Self::Settings => 's',
            Self::PushPromise => 'u',
            Self::Ping => 'i',
            Self::GoAway => 'g',
            Self::WindowUpdate => 'w',
            Self::Continuation => 'c',
            Self::Unknown(_) => '?',
        }
    }
}

/// HTTP/2 priority information
#[derive(Debug, Clone)]
pub struct PriorityInfo {
    /// Stream ID
    pub stream_id: u32,
    /// Stream dependency
    pub dependency: u32,
    /// Weight
    pub weight: u8,
    /// Exclusive flag
    pub exclusive: bool,
}

/// Parsed HTTP/2 connection preface
#[derive(Debug, Clone, Default)]
pub struct Http2Preface {
    /// Settings from SETTINGS frame
    pub settings: BTreeMap<u16, u32>,
    /// Order of settings as sent
    pub settings_order: Vec<u16>,
    /// Order of initial frames
    pub frame_order: Vec<FrameType>,
    /// Window update value (if sent)
    pub window_update: Option<u32>,
    /// Priority information
    pub priorities: Vec<PriorityInfo>,
}

impl Http2Preface {
    /// Add a setting value
    pub fn add_setting(&mut self, id: u16, value: u32) {
        self.settings.insert(id, value);
        self.settings_order.push(id);
    }
    
    /// Add an observed frame type
    pub fn add_frame(&mut self, frame_type: FrameType) {
        self.frame_order.push(frame_type);
    }
}

/// HTTP/2 fingerprint
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Http2Fingerprint {
    /// Full fingerprint string
    pub fingerprint: String,
    /// Settings component
    pub settings_fingerprint: String,
    /// Frame order component
    pub frame_order_fingerprint: String,
    /// Priority tree component
    pub priority_fingerprint: String,
}

impl Http2Fingerprint {
    /// Compute HTTP/2 fingerprint from connection preface
    pub fn compute(preface: &Http2Preface) -> Self {
        // Settings fingerprint: ordered settings with values
        let settings_str: String = preface.settings_order.iter()
            .filter_map(|id| preface.settings.get(id).map(|v| format!("{}:{}", id, v)))
            .collect::<Vec<_>>()
            .join(",");
        let settings_fingerprint = truncated_sha256(&settings_str, 12);
        
        // Frame order fingerprint
        let frame_str: String = preface.frame_order.iter()
            .map(|f| f.to_char())
            .collect();
        let frame_order_fingerprint = truncated_sha256(&frame_str, 8);
        
        // Priority fingerprint
        let priority_str: String = preface.priorities.iter()
            .map(|p| format!("{}:{}:{}:{}", 
                p.stream_id, 
                p.dependency, 
                p.weight,
                if p.exclusive { "e" } else { "_" }
            ))
            .collect::<Vec<_>>()
            .join(",");
        let priority_fingerprint = if priority_str.is_empty() {
            "none".to_string()
        } else {
            truncated_sha256(&priority_str, 8)
        };
        
        let fingerprint = format!("{}|{}|{}", 
            settings_fingerprint, 
            frame_order_fingerprint,
            priority_fingerprint
        );
        
        Self {
            fingerprint,
            settings_fingerprint,
            frame_order_fingerprint,
            priority_fingerprint,
        }
    }
    
    /// Known browser patterns (approximate)
    pub fn likely_browser(&self) -> Option<&'static str> {
        // These are simplified patterns - real implementation would have
        // a more comprehensive database
        match self.settings_fingerprint.as_str() {
            // Chrome typically: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, 
            // INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144
            _ if self.has_chrome_pattern() => Some("Chrome-like"),
            _ if self.has_firefox_pattern() => Some("Firefox-like"),
            _ if self.has_safari_pattern() => Some("Safari-like"),
            _ => None,
        }
    }
    
    fn has_chrome_pattern(&self) -> bool {
        // Chrome SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
        // INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144
        // Settings fingerprint uses ordered "id:value" pairs hashed via SHA-256.
        let chrome_settings = "1:65536,2:0,4:6291456,6:262144";
        self.settings_fingerprint == truncated_sha256(chrome_settings, 12)
    }
    
    fn has_firefox_pattern(&self) -> bool {
        // Firefox SETTINGS: HEADER_TABLE_SIZE=65536,
        // INITIAL_WINDOW_SIZE=131072, MAX_FRAME_SIZE=16384
        let firefox_settings = "1:65536,4:131072,5:16384";
        self.settings_fingerprint == truncated_sha256(firefox_settings, 12)
    }
    
    fn has_safari_pattern(&self) -> bool {
        // Safari/WebKit SETTINGS: HEADER_TABLE_SIZE=4096, ENABLE_PUSH=0,
        // MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=2097152,
        // MAX_HEADER_LIST_SIZE=196608
        let safari_settings = "1:4096,2:0,3:100,4:2097152,6:196608";
        self.settings_fingerprint == truncated_sha256(safari_settings, 12)
    }
}

/// Known HTTP/2 fingerprint patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHttp2Pattern {
    /// Pattern name
    pub name: String,
    /// Expected settings
    pub expected_settings: BTreeMap<u16, u32>,
    /// Expected frame order prefix
    pub expected_frame_order: Vec<FrameType>,
    /// Is this a known bot pattern?
    pub is_bot: bool,
}

impl KnownHttp2Pattern {
    /// Chrome pattern
    pub fn chrome() -> Self {
        let mut settings = BTreeMap::new();
        settings.insert(1, 65536);     // HEADER_TABLE_SIZE
        settings.insert(2, 0);         // ENABLE_PUSH
        settings.insert(4, 6291456);   // INITIAL_WINDOW_SIZE
        settings.insert(6, 262144);    // MAX_HEADER_LIST_SIZE
        
        Self {
            name: "Chrome".to_string(),
            expected_settings: settings,
            expected_frame_order: vec![FrameType::Settings, FrameType::WindowUpdate],
            is_bot: false,
        }
    }
    
    /// Firefox pattern
    pub fn firefox() -> Self {
        let mut settings = BTreeMap::new();
        settings.insert(1, 65536);
        settings.insert(4, 131072);
        settings.insert(5, 16384);
        
        Self {
            name: "Firefox".to_string(),
            expected_settings: settings,
            expected_frame_order: vec![FrameType::Settings],
            is_bot: false,
        }
    }
    
    /// Curl pattern (often used in bots)
    pub fn curl() -> Self {
        let mut settings = BTreeMap::new();
        settings.insert(1, 4096);
        settings.insert(3, 100);
        settings.insert(4, 1073741824);
        
        Self {
            name: "curl".to_string(),
            expected_settings: settings,
            expected_frame_order: vec![FrameType::Settings],
            is_bot: false, // Not necessarily a bot
        }
    }
    
    /// Check if the preface matches this pattern
    pub fn matches(&self, preface: &Http2Preface) -> bool {
        // Check settings match
        for (id, expected_value) in &self.expected_settings {
            match preface.settings.get(id) {
                Some(value) if value == expected_value => continue,
                _ => return false,
            }
        }
        
        // Check frame order prefix matches
        for (i, expected_frame) in self.expected_frame_order.iter().enumerate() {
            if preface.frame_order.get(i) != Some(expected_frame) {
                return false;
            }
        }
        
        true
    }
}

/// Compute truncated SHA256 hash
fn truncated_sha256(input: &str, hex_len: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..hex_len / 2])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chrome_pattern() {
        let mut preface = Http2Preface::default();
        preface.add_setting(1, 65536);
        preface.add_setting(2, 0);
        preface.add_setting(4, 6291456);
        preface.add_setting(6, 262144);
        preface.add_frame(FrameType::Settings);
        preface.add_frame(FrameType::WindowUpdate);
        
        let pattern = KnownHttp2Pattern::chrome();
        assert!(pattern.matches(&preface));
    }
    
    #[test]
    fn test_fingerprint_compute() {
        let mut preface = Http2Preface::default();
        preface.add_setting(1, 4096);
        preface.add_setting(3, 100);
        preface.add_frame(FrameType::Settings);
        
        let fp = Http2Fingerprint::compute(&preface);
        assert!(!fp.fingerprint.is_empty());
        assert!(!fp.settings_fingerprint.is_empty());
    }
    
    #[test]
    fn test_frame_type_parsing() {
        assert_eq!(FrameType::from_byte(0x1), FrameType::Headers);
        assert_eq!(FrameType::from_byte(0x4), FrameType::Settings);
        assert_eq!(FrameType::Headers.to_char(), 'h');
    }
}
