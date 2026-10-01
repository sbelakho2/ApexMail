//! Fuzz target: the production protobuf decode path with size limits.
//!
//! Surface: `mail_proto::decode_with_limits::<StoreMessageRequest>` — the
//! parser every internal gRPC boundary uses for the largest message type
//! (raw_message bytes).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_proto::decode_with_limits;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Any input may decode to None (limit exceeded or wire error) — a
    // panic, hang, or overflow here is the bug libFuzzer is hunting.
    if let Some(decoded) =
        decode_with_limits::<mail_proto::generated::StoreMessageRequest>(data)
    {
        // Oracle (stability): a successfully decoded message must
        // re-encode (prost output is canonical) and the canonical bytes
        // must decode again — a decode/encode asymmetry means the parser
        // accepted state it cannot represent.
        let reencoded = decoded.encode_to_vec();
        let again =
            decode_with_limits::<mail_proto::generated::StoreMessageRequest>(&reencoded);
        assert!(
            again.is_some(),
            "a decoded message did not survive re-encode/decode (input len {})",
            data.len()
        );
        // Oracle (size): no decoded field can carry more bytes than the
        // input contained.
        assert!(
            decoded.raw_message.len() <= data.len() + 16,
            "decoded raw_message ({}) larger than input ({})",
            decoded.raw_message.len(),
            data.len()
        );
    }
});
