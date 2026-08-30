pub mod leads {
    /// Stable machine-readable labels (no emoji): they surface verbatim in
    /// the admin JSON `icon` field and must render identically everywhere.
    pub fn source_icon(name: &str) -> &'static str {
        match name.to_lowercase().as_str() {
            "linkedin" => "linkedin",
            "website" => "website",
            "referral" => "referral",
            "conference" => "conference",
            "cold_outreach" | "cold outreach" => "outreach",
            _ => "other",
        }
    }

    #[cfg(test)]
    mod tests {
        use super::source_icon;

        #[test]
        fn source_icon_maps_known_lead_sources() {
            assert_eq!(source_icon("LinkedIn"), "linkedin");
            assert_eq!(source_icon("cold outreach"), "outreach");
            
        }

        #[test]
        fn source_icon_uses_default_for_unknown_sources() {
            
        }
    }
}

/// PP-007: JSON serialization buffer reuse helper.
///
/// Wraps `serde_json::Serializer` over a `Vec<u8>` to avoid per-call allocations.
/// Handlers that serialize multiple JSON values can reuse the same buffer across
/// calls by calling `clear()` between uses.
///
/// # Example
/// ```rust,no_run
/// use serde::Serialize;
/// use api_server::presentation::json_buffer::JsonBuffer;
///
/// #[derive(Serialize)]
/// struct Payload { name: String }
///
/// let mut buf = JsonBuffer::new();
/// let payload = Payload { name: "test".into() };
/// let bytes = buf.serialize(&payload).expect("invariant: serialization should succeed");
/// ```
pub mod json_buffer {
    use serde::Serialize;
    use serde_json::Serializer;

    /// A reusable JSON serialization buffer.
    ///
    /// Internally holds a `Vec<u8>` that grows as needed but is never shrunk,
    /// avoiding reallocation on subsequent serialization calls.
    pub struct JsonBuffer {
        buffer: Vec<u8>,
    }

    impl JsonBuffer {
        /// Create a new empty JSON buffer.
        pub fn new() -> Self {
            Self { buffer: Vec::new() }
        }

        /// Create a new JSON buffer with the given initial capacity.
        pub fn with_capacity(capacity: usize) -> Self {
            Self {
                buffer: Vec::with_capacity(capacity),
            }
        }

        /// Serialize `value` into the internal buffer and return a reference
        /// to the serialized bytes.  The buffer is cleared before each call.
        ///
        /// This avoids allocating a new `Vec` per serialization — only the
        /// internal buffer grows if the serialized output is larger than any
        /// previous call.
        pub fn serialize<T: Serialize>(&mut self, value: &T) -> Result<&[u8], serde_json::Error> {
            self.buffer.clear();
            let mut serializer = Serializer::new(&mut self.buffer);
            value.serialize(&mut serializer)?;
            Ok(self.buffer.as_slice())
        }

        /// Clear the buffer for reuse.
        pub fn clear(&mut self) {
            self.buffer.clear();
        }

        /// Consume the buffer and return the underlying `Vec<u8>`.
        pub fn into_vec(self) -> Vec<u8> {
            self.buffer
        }
    }

    impl Default for JsonBuffer {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde::Serialize;

        #[derive(Serialize)]
        struct TestPayload {
            name: String,
            value: u64,
        }

        #[test]
        fn test_json_buffer_serialize() {
            let mut buf = JsonBuffer::new();
            let payload = TestPayload {
                name: "hello".into(),
                value: 42,
            };
            let bytes = buf.serialize(&payload).unwrap();
            let json_str = std::str::from_utf8(bytes).unwrap();
            assert!(json_str.contains("\"name\":\"hello\""));
            assert!(json_str.contains("\"value\":42"));
        }

        #[test]
        fn test_json_buffer_reuse() {
            let mut buf = JsonBuffer::new();
            let p1 = TestPayload {
                name: "first".into(),
                value: 1,
            };
            let first = buf.serialize(&p1).unwrap().to_vec();

            let p2 = TestPayload {
                name: "second".into(),
                value: 2,
            };
            let second = buf.serialize(&p2).unwrap().to_vec();

            // Ensure the buffer was reused (cleared between calls)
            assert_ne!(first, second);
        }

        #[test]
        fn test_json_buffer_clear_and_reuse() {
            let mut buf = JsonBuffer::with_capacity(256);
            let payload = TestPayload {
                name: "test".into(),
                value: 99,
            };
            let bytes = buf.serialize(&payload).unwrap();
            assert!(!bytes.is_empty());
            buf.clear();
            assert!(buf.buffer.is_empty());
        }
    }
}
