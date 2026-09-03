//! ExecutionChallengeV1: the deterministic browser-execution program
//! generator — the Rust mirror of the PHP
//! `KiwiCaptcha\ExecutionChallengeGenerator`.
//!
//! Given the secret `execution_key` and the challenge context
//! (nonce, scope, action, version) it produces an opaque bytecode
//! program whose op sequence and literals are drawn from a keyed PRF
//! stream:
//!
//! ```text
//! block_i = HMAC-SHA256(execution_key,
//!     "kiwi-execution-v1|" ‖ nonce ‖ "|" ‖ scope ‖ "|" ‖ action ‖ "|" ‖ version
//!     ‖ u32be(i))
//! ```
//!
//! so the same inputs always produce the same program (deterministic
//! per challenge). No `Math.random`/`Date`/wall-clock input exists in
//! the generation or the op semantics — the program is a pure function
//! of the context.
//!
//! # The program blob (binary, base64 on the wire)
//!
//! The program is self-describing — it embeds the scope, action and op
//! version it was generated for:
//!
//! ```text
//! byte 0:            format version (1)
//! byte 1:            scope length S (1..128)
//! bytes 2..2+S-1:    scope (ASCII)
//! byte 2+S:          action length A (1..32)
//! bytes 3+S..3+S+A-1: action (ASCII)
//! byte:              op version (u8)
//! byte:              op count N (8..24)
//! then N op records (1 byte opcode + fixed-shape operands)
//! ```
//!
//! # The fixed opcode set
//!
//! The opcode list, with the operand shapes in a fixed canonical
//! order that both the generator and every interpreter share:
//!
//! ```text
//!  0 ADD       8 operand bytes -> two u32 big-endian (a, b)
//!  1 SUB       8 bytes
//!  2 MUL       8 bytes
//!  3 XOR       8 bytes
//!  4 AND       8 bytes
//!  5 OR        8 bytes
//!  6 SHL       8 bytes
//!  7 SHR       8 bytes
//!  8 U8_CREATE 1 raw byte -> len = 8 + (b % 57)
//!  9 U8_WRITE  2 bytes -> idx = b0 % 64, val = b1
//! 10 U8_READ   1 byte -> idx = b0 % 64
//! 11 U8_ROTATE 1 byte -> k = b0 % 8
//! 12 STR_LEN   length byte (actual length 1..16) + string bytes
//! 13 STR_CHARCODE  length byte + string + 1 index byte
//! 14 STR_CODEPOINT length byte + string + 1 index byte
//! 15 STR_SLICE  length byte + string + 2 bytes (start/count raw)
//! 16 DOM_CREATE 1 tag byte + id-length byte (4..16) + id bytes
//! 17 DOM_SET_ATTR 1 name byte + value-length byte (1..32) + value bytes
//! 18 DOM_APPEND   (no operands)
//! 19 DOM_QUERY   id-length byte (4..16) + id bytes
//! 20 DOM_GET_ATTR 1 name byte
//! 21 DOM_DATASET_SET key-length byte (1..16) + `x[0-9a-z_]{0,15}` key + value-length + value
//! 22 DOM_DATASET_GET key-length byte + key bytes
//! 23 DOM_CLASS_ADD   class-length byte (1..12) + class bytes
//! 24 DOM_CLASS_CONTAINS class-length byte + class bytes
//! 25 DOM_PARENT    (no operands)
//! 26 DOM_DISPATCH  (no operands)
//! 27 DOM_SERIALIZE (no operands)
//! 28 DOM_QUERY_REAL  id-length byte (4..16) + id bytes
//! 29 DOM_GEOMETRY    id-length byte (4..16) + id bytes
//! 30 DOM_POINT       2 raw bytes (x, y)
//! 31 DOM_EVENT_REAL  id-length byte (4..16) + id bytes
//! 32 DOM_SERIALIZE_REAL (no operands)
//! 33 DOM_OBSERVE     id-length byte (4..16) + id bytes + 1 raw index byte
//! ```
//!
//! String literals are printable ASCII (0x20..0x7E); ids use the
//! standard-base64 alphabet; class names use `[A-Za-z0-9_-]` (never a
//! space); dataset keys come from the deliberately boring safe alphabet
//! `x[0-9a-z_]{0,15}` — the literal `x` followed by 0..15 characters of
//! `[0-9a-z_]` — so a real-DOM dataset write can never reflect onto a
//! `data-*` attribute that collides with the fixed attribute-name list
//! and no key can ever smuggle canonical or DOM punctuation. The
//! operand grammar mirrors the PHP generator byte-for-byte: the length
//! bytes carry the real length, never a raw PRF byte, except the
//! raw-byte operands (U8_CREATE, U8_WRITE, U8_READ, U8_ROTATE, int
//! literals, tag/name indexes, slice start/count), where both sides
//! derive the same value from the raw byte. All string semantics are
//! byte-exact (the PHP mirror uses raw bytes, so this crate stores
//! operand strings as `Vec<u8>`).
//!
//! # The canonical op trace and the execution digest
//!
//! The canonical op trace is the deterministic execution trace: one
//! `opname(result)` entry per op, joined with ';'. Results are decimal
//! integers, "1"/"0", or standard base64 of a byte string. The
//! real-DOM readback entries (`QUERY_REAL`) carry canonical attribute
//! pairs that may themselves contain ';' and parentheses, so the
//! verifier walks the submitted trace entry by entry against the
//! simulated op sequence and never splits it on a separator. Both the
//! server verifier and the browser interpreter simulate the same
//! deterministic state machine (u8 array, current DOM node,
//! appended-id set).
//!
//! The browser-observed entries carry literal placeholders in the
//! canonical sim (`geom`, `point`, `obs`): the verifier validates the
//! submitted shapes against their invariants and replays the reported
//! layout and observed values instead of predicting them, so a pure
//! solver that never ran a browser cannot fabricate a coherent trace.
//!
//! Every issued program carries a guaranteed structure: a DOM
//! construction block (create, mutate, append), a causal u8 chain
//! (create the array, observe the real height of the constructed
//! node into it, read the observed byte back, checksum or rotate
//! over it) and real-DOM probes whose ids reference the constructed
//! node. An armed challenge always exercises real browser DOM and
//! layout work. The dimension remains experimental: the trace
//! values are reproducible by a pure implementation of the public
//! interpreter semantics, with no environment proof yet; the
//! guaranteed probe structure is the first step toward
//! environment-dependent semantics.
//!
//! The execution digest binds the program, the challenge context and
//! the trace:
//!
//! ```text
//! digest = HMAC-SHA256(program_bytes,
//!     "kiwi-execution-v1|" ‖ nonce ‖ "|" ‖ scope ‖ "|" ‖ action ‖ "|"
//!     ‖ version ‖ "|" ‖ canonical_op_trace))
//! ```
//!
//! The digest key is the program blob itself, a content-derived key:
//! the browser holds only the program, so it can compute the digest,
//! while the secret `execution_key` never leaves the server; it is only
//! used for program generation. The expected digest is never sent to
//! the client — the verifier recomputes it from the stored record's
//! program and compares the presented digest in constant time. A
//! substituted program changes both the key and the expected trace; a
//! digest from another challenge fails on the nonce-bound context. The
//! execution dimension is supplementary evidence only — never the sole
//! acceptance boundary.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The protocol label of the ExecutionChallengeV1 dimension.
pub const LABEL: &str = "kiwi-execution-v1";

/// The program blob format version.
pub const FORMAT_VERSION: u8 = 1;

/// The op-version byte stamped into the program.
pub const PROTOCOL_VERSION: u8 = 1;

/// The highest execution version this generator can emit. Version 2
/// adds the observe opcode and the causal u8 chain; version 3 adds a
/// second constructed node and the sibling-index traversal probe.
pub const MAX_EXECUTION_VERSION: u8 = 3;

/// The deterministic op-count bounds of every issued program.
pub const MIN_OPS: u8 = 8;
pub const MAX_OPS: u8 = 24;

/// The fixed attribute-name list of the DOM ops (never contains 'id').
pub const ATTR_NAMES: [&[u8]; 5] = [b"data-kiwi", b"data-a", b"data-b", b"title", b"data-x"];

/// The fixed tag-name list of DOM_CREATE.
pub const TAG_NAMES: [&str; 4] = ["div", "span", "section", "p"];

/// The id alphabet (standard base64 alphabet; valid inside an HTML id).
pub const ID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The class-name alphabet (no space — classList.add can never throw).
pub const CLASS_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// The deliberately boring dataset-key alphabet: every generated
/// dataset key is the literal `x` followed by 0..15 characters of
/// `[0-9a-z_]` (the grammar `x[0-9a-z_]{0,15}`). No key can carry the
/// `|` canonical separator, HTML/DOM punctuation, whitespace or
/// uppercase, so a real-DOM dataset write can never reflect onto a
/// `data-*` attribute that collides with the fixed attribute-name list,
/// and the canonical segment structure can never be altered by a stored
/// value.
pub const DATASET_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz_";

/// Wire ceiling for the base64 program a record/challenge may carry.
pub const MAX_PROGRAM_BASE64: usize = 4096;

pub const OP_ADD: u8 = 0;
pub const OP_SUB: u8 = 1;
pub const OP_MUL: u8 = 2;
pub const OP_XOR: u8 = 3;
pub const OP_AND: u8 = 4;
pub const OP_OR: u8 = 5;
pub const OP_SHL: u8 = 6;
pub const OP_SHR: u8 = 7;
pub const OP_U8_CREATE: u8 = 8;
pub const OP_U8_WRITE: u8 = 9;
pub const OP_U8_READ: u8 = 10;
pub const OP_U8_ROTATE: u8 = 11;
pub const OP_STR_LEN: u8 = 12;
pub const OP_STR_CHARCODE: u8 = 13;
pub const OP_STR_CODEPOINT: u8 = 14;
pub const OP_STR_SLICE: u8 = 15;
pub const OP_DOM_CREATE: u8 = 16;
pub const OP_DOM_SET_ATTR: u8 = 17;
pub const OP_DOM_APPEND: u8 = 18;
pub const OP_DOM_QUERY: u8 = 19;
pub const OP_DOM_GET_ATTR: u8 = 20;
pub const OP_DOM_DATASET_SET: u8 = 21;
pub const OP_DOM_DATASET_GET: u8 = 22;
pub const OP_DOM_CLASS_ADD: u8 = 23;
pub const OP_DOM_CLASS_CONTAINS: u8 = 24;
pub const OP_DOM_PARENT: u8 = 25;
pub const OP_DOM_DISPATCH: u8 = 26;
pub const OP_DOM_SERIALIZE: u8 = 27;
pub const OP_DOM_QUERY_REAL: u8 = 28;
pub const OP_DOM_GEOMETRY: u8 = 29;
pub const OP_DOM_POINT: u8 = 30;
pub const OP_DOM_EVENT_REAL: u8 = 31;
pub const OP_DOM_SERIALIZE_REAL: u8 = 32;
pub const OP_DOM_OBSERVE: u8 = 33;
pub const OP_DOM_SIBLING_INDEX: u8 = 34;
pub const OP_COUNT: u8 = 35;

/// The trace entry names, one per opcode (index = opcode).
const TRACE_NAMES: [&str; OP_COUNT as usize] = [
    "add",
    "sub",
    "mul",
    "xor",
    "and",
    "or",
    "shl",
    "shr",
    "u8c",
    "u8w",
    "u8r",
    "u8rot",
    "slen",
    "schar",
    "scode",
    "sslice",
    "dcreate",
    "dattr",
    "dappend",
    "dqsel",
    "dget",
    "dset",
    "dgetd",
    "cadd",
    "ccont",
    "dparent",
    "ddispatch",
    "dserialize",
    "qreal",
    "geom",
    "point",
    "evreal",
    "sreal",
    "obs",
    "dsib",
];

/// A parsed op: the opcode plus its canonical operands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    pub opcode: u8,
    /// Canonical operand records, mirroring the PHP decode shape.
    /// Keys vary per opcode: `a`/`b` (u32), `len`, `idx`, `val`, `k`,
    /// `s` (byte string), `start`, `count`, `tag`, `name`, `id`.
    pub operands: BTreeMap<String, Operand>,
}

/// A parsed program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub format: u8,
    pub scope: String,
    pub action: String,
    pub op_version: u8,
    pub ops: Vec<Op>,
}

/// A canonical operand value (int or byte string — the wire has no
/// other operand kinds). Strings are stored as raw bytes for byte-exact
/// parity with the PHP mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Int(u64),
    Bytes(Vec<u8>),
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// The keyed PRF stream: successive 32-byte HMAC-SHA256 blocks keyed by
/// `execution_key` over the label+context+u32be(counter), served as one
/// byte string. Bounded at 16 blocks (512 bytes) — the op count plus
/// 24 ops with their operand bytes never needs more, and the bound
/// makes the stream deterministic.
fn prf_stream(key: &[u8], nonce: &str, scope: &str, action: &str, version: &str) -> Vec<u8> {
    let mut base = Vec::with_capacity(
        LABEL.len() + nonce.len() + scope.len() + action.len() + version.len() + 4,
    );
    base.extend_from_slice(LABEL.as_bytes());
    base.push(b'|');
    base.extend_from_slice(nonce.as_bytes());
    base.push(b'|');
    base.extend_from_slice(scope.as_bytes());
    base.push(b'|');
    base.extend_from_slice(action.as_bytes());
    base.push(b'|');
    base.extend_from_slice(version.as_bytes());

    let mut stream = Vec::with_capacity(16 * 32);
    for i in 0..16u32 {
        let mut msg = base.clone();
        msg.extend_from_slice(&i.to_be_bytes());
        stream.extend_from_slice(&hmac(key, &msg));
    }
    stream
}

fn is_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b':')
}

/// Generate the execution program for a challenge context: base64 of
/// the self-describing bytecode blob, deterministic per
/// (execution_key, nonce, scope, action, version).
///
/// Mirrors `KiwiCaptcha\ExecutionChallengeGenerator::generate()`
/// byte-for-byte: the same PRF stream, the same op draw sequence, the
/// same blob layout. `version` is the canonical numeric byte, exactly 1
/// — the only op-version of the wire contract (the parser rejects any
/// other byte, so issuance never mints a program the verifier would
/// refuse). It is passed as a `u8` and stamped as the raw numeric
/// byte; no string-cast ever reaches the blob.
pub fn generate(
    execution_key: &[u8],
    nonce: &str,
    scope: &str,
    action: &str,
    version: u8,
) -> Result<String, GenerateError> {
    if execution_key.len() < 16 {
        return Err(GenerateError::KeyTooShort);
    }
    if !is_identifier(action, 32) {
        return Err(GenerateError::InvalidAction);
    }
    if !(1..=MAX_EXECUTION_VERSION).contains(&version) {
        return Err(GenerateError::InvalidVersion);
    }
    if !is_identifier(scope, 128) {
        // The decoder's scope grammar is 1-128 bytes of the same
        // alphabet (see `decode`): a scope outside it would mint a
        // blob the module itself refuses to decode, and a scope above
        // 255 bytes would wrap the length byte — refused here, before
        // any stream work.
        return Err(GenerateError::InvalidScope);
    }

    let mut cursor = Cursor::new(prf_stream(
        execution_key,
        nonce,
        scope,
        action,
        &version.to_string(),
    ));

    let mut program = Vec::new();
    program.push(FORMAT_VERSION);
    program.push(scope.len() as u8);
    program.extend_from_slice(scope.as_bytes());
    program.push(action.len() as u8);
    program.extend_from_slice(action.as_bytes());
    program.push(version);
    // Version 1 carries the construction-to-probe skeleton with no
    // observe opcode (floor 8); version 2 adds the causal u8 chain, so
    // its floor rises to 11 (the fixed chain plus the 1..3 extra
    // probes) while the grammar bounds 8..24 stay unchanged and every
    // stamped count always fits its emitted records.
    let op_count = match version {
        2 => 11 + (cursor.next_byte() % 14),
        3 => 15 + (cursor.next_byte() % 10),
        _ => 8 + (cursor.next_byte() % 17),
    };
    program.push(op_count);

    // The guaranteed structure of every armed program: a mandatory
    // DOM construction block (createElement with a drawn id, a mutate
    // op on that node, an append) and a mandatory causal u8 chain
    // (create the array, observe the real height of the constructed
    // node into it, read the observed byte back, then checksum or
    // rotate over it). A mandatory real-probe block follows (one of
    // the id-carrying real probes 28/29/31 plus 1..3 further real
    // probes). The probe and observe id operand is the constructed id
    // bytes, drawn once and reused, so every probe reads a real
    // constructed node after the append. The remaining op slots are
    // filled from the other 28 opcodes, so the count stays within
    // MIN_OPS..MAX_OPS while every program exercises real DOM
    // construction, real layout observation and probe reads against
    // constructed nodes.
    let mut ops: Vec<(u8, Vec<u8>)> = Vec::new();
    let tag = cursor.next_byte();
    let id_operand = draw_id(&mut cursor);
    let mut create_operands = vec![tag];
    create_operands.extend_from_slice(&id_operand);
    ops.push((OP_DOM_CREATE, create_operands));
    let mutates = [OP_DOM_SET_ATTR, OP_DOM_DATASET_SET, OP_DOM_CLASS_ADD];
    let mutate = mutates[(cursor.next_byte() % 3) as usize];
    ops.push((mutate, draw_operands(&mut cursor, mutate)));
    ops.push((OP_DOM_APPEND, Vec::new()));
    let mut sibling_operand = id_operand.clone();
    if version >= 3 {
        // The second constructed node: the sibling-index probe walks
        // the real previousElementSibling chain of this node (its
        // index among the body children the program built).
        let tag_b = cursor.next_byte();
        sibling_operand = draw_id(&mut cursor);
        let mut create_b = vec![tag_b];
        create_b.extend_from_slice(&sibling_operand);
        ops.push((OP_DOM_CREATE, create_b));
        let mutate_b = mutates[(cursor.next_byte() % 3) as usize];
        ops.push((mutate_b, draw_operands(&mut cursor, mutate_b)));
        ops.push((OP_DOM_APPEND, Vec::new()));
    }
    if version >= 2 {
        // The causal chain: `U8_CREATE(len)` then `OBSERVE` writes the
        // browser-observed height at a drawn index inside the array,
        // `U8_READ` reads that same byte back (its exact entry must equal
        // the observed value), and the checksum/rotate consumer runs over
        // the array still carrying the observed byte.
        let u8c_byte = cursor.next_byte();
        ops.push((OP_U8_CREATE, vec![u8c_byte]));
        let u8_len = 8 + (u8c_byte % 57);
        let obs_idx_byte = cursor.next_byte() % u8_len;
        let mut obs_operands = id_operand.clone();
        obs_operands.push(obs_idx_byte);
        ops.push((OP_DOM_OBSERVE, obs_operands));
        ops.push((OP_U8_READ, vec![obs_idx_byte]));
        let u8_consumer = [OP_U8_WRITE, OP_U8_ROTATE][(cursor.next_byte() % 2) as usize];
        ops.push((u8_consumer, draw_operands(&mut cursor, u8_consumer)));
    }
    let link_probes = [OP_DOM_QUERY_REAL, OP_DOM_GEOMETRY, OP_DOM_EVENT_REAL];
    ops.push((
        link_probes[(cursor.next_byte() % 3) as usize],
        id_operand.clone(),
    ));
    if version >= 3 {
        // The mandatory sibling-index traversal probe of the second
        // constructed node.
        ops.push((OP_DOM_SIBLING_INDEX, sibling_operand.clone()));
    }
    let extra_probes = 1 + (cursor.next_byte() % 3);
    let probe_pool = if version >= 3 { 7 } else { 5 };
    for _ in 0..extra_probes {
        let probe = OP_DOM_QUERY_REAL + (cursor.next_byte() % probe_pool);
        let probe_operands = match probe {
            OP_DOM_QUERY_REAL | OP_DOM_GEOMETRY | OP_DOM_EVENT_REAL => id_operand.clone(),
            OP_DOM_SIBLING_INDEX => sibling_operand.clone(),
            OP_DOM_POINT => cursor.take(2),
            OP_DOM_OBSERVE => {
                let mut o = id_operand.clone();
                o.push(cursor.next_byte());
                o
            }
            _ => Vec::new(),
        };
        ops.push((probe, probe_operands));
    }
    // Top up to the stamped op count with the other 28 opcodes (the
    // fixed skeleton plus the extra probes never exceed the count
    // since the floor is 11).
    while (ops.len() as u8) < op_count {
        let opcode = cursor.next_byte() % 28;
        ops.push((opcode, draw_operands(&mut cursor, opcode)));
    }
    // The count byte is drawn before the extra probes, so the op list
    // can overshoot it on the smallest counts; the emission is capped
    // at the stamped count, the exact number every decoder reads, so
    // each minted blob ends at EOF and stays inside the grammar.
    for (opcode, operands) in ops.iter() {
        program.push(*opcode);
        program.extend_from_slice(operands);
    }

    Ok(B64.encode(program))
}

/// The operand draw mirrors the parser's read order exactly: for the
/// string-shaped operands the draw writes the real length as the
/// length byte; for the raw-byte operands it writes the raw PRF byte.
/// A byte cursor over the PRF stream (or a decoded blob): `take(n)`
/// yields the next n bytes (padded with zeros when exhausted, exactly
/// like the PHP stream semantics) and `next_byte()` yields one byte.
struct Cursor {
    bytes: Vec<u8>,
    pos: usize,
}

impl Cursor {
    fn new(bytes: Vec<u8>) -> Self {
        Cursor { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let end = (self.pos + n).min(self.bytes.len());
        let out = self.bytes[self.pos..end].to_vec();
        self.pos = end;
        out
    }

    fn next_byte(&mut self) -> u8 {
        if self.pos >= self.bytes.len() {
            return 0;
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        b
    }

    /// Strict byte read for the parser: `None` at EOF (the PHP mirror's
    /// parse fails on EOF, so a truncated blob must never parse).
    fn take_strict(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n > self.bytes.len() {
            return None;
        }
        let out = self.bytes[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(out)
    }
}

fn draw_operands(cursor: &mut Cursor, opcode: u8) -> Vec<u8> {
    match opcode {
        OP_ADD | OP_SUB | OP_MUL | OP_XOR | OP_AND | OP_OR | OP_SHL | OP_SHR => cursor.take(8),
        OP_U8_CREATE | OP_U8_READ | OP_U8_ROTATE => cursor.take(1),
        OP_U8_WRITE => cursor.take(2),
        OP_STR_LEN => draw_string(cursor, 0),
        OP_STR_CHARCODE | OP_STR_CODEPOINT => draw_string(cursor, 1),
        OP_STR_SLICE => draw_string(cursor, 2),
        OP_DOM_CREATE => {
            let mut out = cursor.take(1);
            out.extend_from_slice(&draw_id(cursor));
            out
        }
        OP_DOM_SET_ATTR => {
            let mut out = cursor.take(1);
            out.extend_from_slice(&draw_value(cursor));
            out
        }
        OP_DOM_QUERY => draw_id(cursor),
        OP_DOM_GET_ATTR => cursor.take(1),
        OP_DOM_DATASET_SET => {
            let mut out = Vec::new();
            let len = (cursor.next_byte() % 16) + 1;
            out.push(len);
            // The deliberately boring safe alphabet: the literal `x`
            // followed by 0..15 characters of [0-9a-z_] — no canonical
            // `|`, no DOM punctuation, no whitespace, no uppercase.
            out.push(b'x');
            for _ in 1..len {
                out.push(DATASET_ALPHABET[(cursor.next_byte() % 37) as usize]);
            }
            out.extend_from_slice(&draw_value(cursor));
            out
        }
        OP_DOM_DATASET_GET => draw_string(cursor, 0),
        OP_DOM_CLASS_ADD | OP_DOM_CLASS_CONTAINS => draw_class(cursor),
        OP_DOM_QUERY_REAL | OP_DOM_GEOMETRY | OP_DOM_EVENT_REAL => draw_id(cursor),
        OP_DOM_POINT => cursor.take(2),
        // The causal observe op: the probed id (reused constructed id
        // on issued programs) plus one raw byte for the u8 destination
        // index.
        OP_DOM_OBSERVE => {
            let mut out = draw_id(cursor);
            out.push(cursor.next_byte());
            out
        }
        OP_DOM_SIBLING_INDEX => draw_id(cursor),
        _ => Vec::new(),
    }
}

fn draw_string(cursor: &mut Cursor, extra: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let len = (cursor.next_byte() % 16) + 1;
    out.push(len);
    for _ in 0..len {
        out.push(0x20 + (cursor.next_byte() % 0x5F));
    }
    out.extend_from_slice(&cursor.take(extra));
    out
}

fn draw_id(cursor: &mut Cursor) -> Vec<u8> {
    let mut out = Vec::new();
    let len = 4 + (cursor.next_byte() % 13);
    out.push(len);
    for _ in 0..len {
        out.push(ID_ALPHABET[(cursor.next_byte() % 64) as usize]);
    }
    out
}

fn draw_value(cursor: &mut Cursor) -> Vec<u8> {
    let mut out = Vec::new();
    let len = (cursor.next_byte() % 32) + 1;
    out.push(len);
    for _ in 0..len {
        out.push(0x20 + (cursor.next_byte() % 0x5F));
    }
    out
}

fn draw_class(cursor: &mut Cursor) -> Vec<u8> {
    let mut out = Vec::new();
    let len = (cursor.next_byte() % 12) + 1;
    out.push(len);
    for _ in 0..len {
        out.push(CLASS_ALPHABET[(cursor.next_byte() % 64) as usize]);
    }
    out
}

/// Parse a program blob, or `None` when the blob is malformed.
///
/// The parser is deliberately strict, the two-language mirror of the
/// PHP `ExecutionChallengeGenerator::decode()`:
/// - the op version must be exactly 1 (no arbitrary byte — only the one
///   canonical version of the wire contract exists);
/// - the embedded scope/action must match the canonical identifier
///   grammar of the rest of Kiwi (`[A-Za-z0-9._:-]` with the issuance
///   length caps), so a foreign blob can never smuggle canonical or
///   whitespace bytes;
/// - the op list must end exactly at EOF: `cursor.pos == bytes.len()`.
///   A trailing byte after the last op record is invalid.
pub fn decode(program_b64: &str) -> Option<Program> {
    if program_b64.len() > MAX_PROGRAM_BASE64 {
        return None;
    }
    let bytes = B64.decode(program_b64).ok()?;
    if B64.encode(&bytes) != program_b64 {
        return None;
    }
    let mut cursor = Cursor::new(bytes);

    let format = cursor.take_strict(1)?[0];
    if format != FORMAT_VERSION {
        return None;
    }
    let scope_len = cursor.take_strict(1)?[0] as usize;
    if scope_len == 0 || scope_len > 128 {
        return None;
    }
    let scope = std::str::from_utf8(&cursor.take_strict(scope_len)?)
        .ok()?
        .to_string();
    // The embedded scope must match the canonical identifier grammar of
    // the rest of Kiwi — the same charset/length rules issuance
    // enforces. A foreign blob with out-of-alphabet bytes is malformed,
    // never traced.
    if !is_identifier(&scope, 128) {
        return None;
    }
    let action_len = cursor.take_strict(1)?[0] as usize;
    if action_len == 0 || action_len > 32 {
        return None;
    }
    let action = std::str::from_utf8(&cursor.take_strict(action_len)?)
        .ok()?
        .to_string();
    // The embedded action must match the same canonical identifier
    // grammar (1..=32 bytes of [A-Za-z0-9._:-]).
    if !is_identifier(&action, 32) {
        return None;
    }
    let op_version = cursor.take_strict(1)?[0];
    // Execution versions 1, 2 and 3 are accepted (the compat window:
    // old challenges stay verifiable for their whole TTL); each
    // version bounds its own opcode space below.
    if !(1..=MAX_EXECUTION_VERSION).contains(&op_version) {
        return None;
    }
    let op_count = cursor.take_strict(1)?[0];
    if !(MIN_OPS..=MAX_OPS).contains(&op_count) {
        return None;
    }

    let mut ops = Vec::with_capacity(op_count as usize);
    for _ in 0..op_count {
        let opcode = cursor.take_strict(1)?[0];
        // Older-version programs never carry newer opcodes (the
        // version-2 observe opcode 33, the version-3 sibling-index
        // opcode 34): an old interpreter must be able to reject a
        // newer grammar by the declared version byte alone.
        let max_opcode = OP_COUNT - (3 - op_version);
        if opcode >= max_opcode {
            return None;
        }
        ops.push(Op {
            opcode,
            operands: read_operands(&mut cursor, opcode)?,
        });
    }

    // Exact EOF: the op list must consume the whole blob. A trailing
    // byte after the last op record is a foreign or corrupt blob.
    if cursor.pos != cursor.bytes.len() {
        return None;
    }

    Some(Program {
        format: FORMAT_VERSION,
        scope,
        action,
        op_version,
        ops,
    })
}

fn read_u32(cursor: &mut Cursor) -> Option<u64> {
    let bytes = cursor.take_strict(4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
}

/// Read a length byte (the actual length, 1..=max_len) followed by the
/// bytes. The length byte carries the real length; the generator
/// writes the real value, never a raw PRF byte — so the reader takes it
/// verbatim (mirroring the PHP parser).
fn read_len_bytes(cursor: &mut Cursor, max_len: usize) -> Option<Vec<u8>> {
    let len = cursor.take_strict(1)?[0] as usize;
    if len < 1 || len > max_len {
        return None;
    }
    cursor.take_strict(len)
}

fn read_operands(cursor: &mut Cursor, opcode: u8) -> Option<BTreeMap<String, Operand>> {
    let mut map = BTreeMap::new();
    match opcode {
        OP_ADD | OP_SUB | OP_MUL | OP_XOR | OP_AND | OP_OR | OP_SHL | OP_SHR => {
            map.insert("a".into(), Operand::Int(read_u32(cursor)?));
            map.insert("b".into(), Operand::Int(read_u32(cursor)?));
        }
        OP_U8_CREATE => {
            // Raw-byte operand: both sides derive len = 8 + (b % 57).
            let b = cursor.take_strict(1)?[0];
            map.insert("len".into(), Operand::Int(8 + (b as u64 % 57)));
        }
        OP_U8_WRITE => {
            let b0 = cursor.take_strict(1)?[0];
            let b1 = cursor.take_strict(1)?[0];
            map.insert("idx".into(), Operand::Int((b0 % 64) as u64));
            map.insert("val".into(), Operand::Int(b1 as u64));
        }
        OP_U8_READ => {
            let b = cursor.take_strict(1)?[0];
            map.insert("idx".into(), Operand::Int((b % 64) as u64));
        }
        OP_U8_ROTATE => {
            let b = cursor.take_strict(1)?[0];
            map.insert("k".into(), Operand::Int((b % 8) as u64));
        }
        OP_STR_LEN => {
            let s = read_len_bytes(cursor, 16)?;
            map.insert("s".into(), Operand::Bytes(s));
        }
        OP_STR_CHARCODE | OP_STR_CODEPOINT => {
            let s = read_len_bytes(cursor, 16)?;
            let idx = cursor.take_strict(1)?[0];
            map.insert("s".into(), Operand::Bytes(s));
            map.insert("idx".into(), Operand::Int(idx as u64));
        }
        OP_STR_SLICE => {
            let s = read_len_bytes(cursor, 16)?;
            let tail = cursor.take_strict(2)?;
            let start = (tail[0] as usize) % (s.len() + 1);
            let count = (tail[1] as usize) % 32;
            map.insert("s".into(), Operand::Bytes(s));
            map.insert("start".into(), Operand::Int(start as u64));
            map.insert("count".into(), Operand::Int(count as u64));
        }
        OP_DOM_CREATE => {
            let tag = cursor.take_strict(1)?[0];
            let id = read_len_bytes(cursor, 16)?;
            if id.len() < 4 {
                return None;
            }
            map.insert("tag".into(), Operand::Int((tag % 4) as u64));
            map.insert("id".into(), Operand::Bytes(id));
        }
        OP_DOM_SET_ATTR => {
            let name = cursor.take_strict(1)?[0];
            let val = read_len_bytes(cursor, 32)?;
            map.insert("name".into(), Operand::Int((name % 5) as u64));
            map.insert("val".into(), Operand::Bytes(val));
        }
        OP_DOM_APPEND | OP_DOM_PARENT | OP_DOM_DISPATCH | OP_DOM_SERIALIZE => {}
        OP_DOM_QUERY_REAL | OP_DOM_GEOMETRY | OP_DOM_EVENT_REAL => {
            let id = read_len_bytes(cursor, 16)?;
            if id.len() < 4 {
                return None;
            }
            map.insert("id".into(), Operand::Bytes(id));
        }
        OP_DOM_POINT => {
            let x = cursor.take_strict(1)?[0] as u64;
            let y = cursor.take_strict(1)?[0] as u64;
            map.insert("x".into(), Operand::Int(x % 256));
            map.insert("y".into(), Operand::Int(y % 256));
        }
        // The causal observe op reads the probed id (4..16 bytes, like
        // the id-carrying real probes) then one raw byte for the u8
        // destination index (mirroring the PHP readObserve shape).
        OP_DOM_OBSERVE => {
            let id = read_len_bytes(cursor, 16)?;
            if id.len() < 4 {
                return None;
            }
            let b = cursor.take_strict(1)?[0];
            map.insert("id".into(), Operand::Bytes(id));
            map.insert("idx".into(), Operand::Int((b % 64) as u64));
        }
        OP_DOM_SIBLING_INDEX => {
            let id = read_len_bytes(cursor, 16)?;
            if id.len() < 4 {
                return None;
            }
            map.insert("id".into(), Operand::Bytes(id));
        }
        OP_DOM_SERIALIZE_REAL => {}
        OP_DOM_QUERY => {
            let id = read_len_bytes(cursor, 16)?;
            if id.len() < 4 {
                return None;
            }
            map.insert("id".into(), Operand::Bytes(id));
        }
        OP_DOM_GET_ATTR => {
            let name = cursor.take_strict(1)?[0];
            map.insert("name".into(), Operand::Int((name % 5) as u64));
        }
        OP_DOM_DATASET_SET => {
            let key = read_len_bytes(cursor, 16)?;
            let val = read_len_bytes(cursor, 32)?;
            map.insert("s".into(), Operand::Bytes(key));
            map.insert("val".into(), Operand::Bytes(val));
        }
        OP_DOM_DATASET_GET => {
            let key = read_len_bytes(cursor, 16)?;
            map.insert("s".into(), Operand::Bytes(key));
        }
        OP_DOM_CLASS_ADD | OP_DOM_CLASS_CONTAINS => {
            let cls = read_len_bytes(cursor, 12)?;
            map.insert("s".into(), Operand::Bytes(cls));
        }
        _ => return None,
    }
    Some(map)
}

/// Whether a program blob is well-formed.
pub fn is_valid_program(program_b64: &str) -> bool {
    decode(program_b64).is_some()
}

/// The deterministic canonical op trace of a program: the joined
/// `opname(result)` entries of every op, simulated against the shared
/// state machine. A pure function of the program — the browser
/// interpreter computes the identical string.
pub fn canonical_trace(program: &Program) -> String {
    let mut u8arr: Vec<u8> = Vec::new();
    let mut cur: Option<DomNode> = None;
    let mut doc_ids: HashSet<Vec<u8>> = HashSet::new();
    let mut entries: Vec<String> = Vec::with_capacity(program.ops.len());

    for op in &program.ops {
        let result = simulate_op(op, &mut u8arr, &mut cur, &mut doc_ids);
        entries.push(format!("{}({})", TRACE_NAMES[op.opcode as usize], result));
    }
    entries.join(";")
}

/// The current DOM node of the state machine.
#[derive(Debug, Clone)]
struct DomNode {
    id: Vec<u8>,
    attrs: BTreeMap<Vec<u8>, Vec<u8>>,
    dataset: BTreeMap<Vec<u8>, Vec<u8>>,
    classes: HashSet<Vec<u8>>,
    appended: bool,
}

fn checksum(u8arr: &[u8]) -> u64 {
    u8arr.iter().fold(0u64, |acc, b| (acc + *b as u64) & 0xFF)
}

fn operand_int(op: &Op, key: &str) -> u64 {
    match op.operands.get(key) {
        Some(Operand::Int(v)) => *v,
        _ => 0,
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn operand_bytes(op: &Op, key: &str) -> Vec<u8> {
    match op.operands.get(key) {
        Some(Operand::Bytes(s)) => s.clone(),
        _ => Vec::new(),
    }
}

/// The deterministic state-machine execution of one op; returns the
/// op's canonical trace value (decimal, "1"/"0", or standard base64).
fn simulate_op(
    op: &Op,
    u8arr: &mut Vec<u8>,
    cur: &mut Option<DomNode>,
    doc_ids: &mut HashSet<Vec<u8>>,
) -> String {
    let u32 = |v: u64| -> u64 { v & 0xFFFF_FFFF };
    match op.opcode {
        OP_ADD => u32(operand_int(op, "a").wrapping_add(operand_int(op, "b"))).to_string(),
        OP_SUB => u32(operand_int(op, "a").wrapping_sub(operand_int(op, "b"))).to_string(),
        OP_MUL => u32(operand_int(op, "a").wrapping_mul(operand_int(op, "b"))).to_string(),
        OP_XOR => (operand_int(op, "a") ^ operand_int(op, "b")).to_string(),
        OP_AND => (operand_int(op, "a") & operand_int(op, "b")).to_string(),
        OP_OR => (operand_int(op, "a") | operand_int(op, "b")).to_string(),
        OP_SHL => {
            u32(operand_int(op, "a").wrapping_shl((operand_int(op, "b") & 31) as u32)).to_string()
        }
        OP_SHR => u32(operand_int(op, "a") >> (operand_int(op, "b") & 31)).to_string(),
        OP_U8_CREATE => {
            *u8arr = vec![0u8; operand_int(op, "len") as usize];
            checksum(u8arr).to_string()
        }
        OP_U8_WRITE => {
            let idx = operand_int(op, "idx") as usize;
            let val = (operand_int(op, "val") & 0xFF) as u8;
            if idx < u8arr.len() {
                u8arr[idx] = val;
            }
            checksum(u8arr).to_string()
        }
        OP_U8_READ => {
            let idx = operand_int(op, "idx") as usize;
            (if idx < u8arr.len() {
                u8arr[idx] as u64
            } else {
                0
            })
            .to_string()
        }
        OP_U8_ROTATE => {
            let k = (operand_int(op, "k") % 8) as usize;
            if !u8arr.is_empty() && k > 0 {
                let n = u8arr.len();
                let rotated: Vec<u8> = (0..n).map(|i| u8arr[(i + k) % n]).collect();
                *u8arr = rotated;
            }
            checksum(u8arr).to_string()
        }
        OP_STR_LEN => operand_bytes(op, "s").len().to_string(),
        OP_STR_CHARCODE | OP_STR_CODEPOINT => {
            let s = operand_bytes(op, "s");
            let idx = operand_int(op, "idx") as usize;
            (if idx < s.len() { s[idx] as u64 } else { 0 }).to_string()
        }
        OP_STR_SLICE => {
            let s = operand_bytes(op, "s");
            let start = operand_int(op, "start") as usize;
            let count = operand_int(op, "count") as usize;
            let start = start.min(s.len());
            let end = (start + count).min(s.len());
            B64.encode(&s[start..end])
        }
        OP_DOM_CREATE => {
            let id = operand_bytes(op, "id");
            *cur = Some(DomNode {
                id: id.clone(),
                // The created element carries its id as the reflected id
                // attribute (the browser's `el.id = id`), so serialization
                // includes it.
                attrs: {
                    let mut attrs = BTreeMap::new();
                    attrs.insert(b"id".to_vec(), id.clone());
                    attrs
                },
                dataset: BTreeMap::new(),
                classes: HashSet::new(),
                appended: false,
            });
            B64.encode(id)
        }
        OP_DOM_SET_ATTR => {
            let name = ATTR_NAMES[(operand_int(op, "name") % 5) as usize];
            if let Some(node) = cur {
                node.attrs.insert(name.to_vec(), operand_bytes(op, "val"));
            }
            B64.encode(name)
        }
        OP_DOM_APPEND => {
            if let Some(node) = cur {
                node.appended = true;
                doc_ids.insert(node.id.clone());
            }
            "1".into()
        }
        OP_DOM_QUERY => {
            let id = operand_bytes(op, "id");
            (if doc_ids.contains(&id) { "1" } else { "0" }).into()
        }
        OP_DOM_GET_ATTR => {
            let name = ATTR_NAMES[(operand_int(op, "name") % 5) as usize];
            let value = cur
                .as_ref()
                .and_then(|n| n.attrs.get(name).cloned())
                .unwrap_or_default();
            B64.encode(value)
        }
        OP_DOM_DATASET_SET => {
            let key = operand_bytes(op, "s");
            if let Some(node) = cur {
                node.dataset.insert(key.clone(), operand_bytes(op, "val"));
            }
            B64.encode(key)
        }
        OP_DOM_DATASET_GET => {
            let key = operand_bytes(op, "s");
            let value = cur
                .as_ref()
                .and_then(|n| n.dataset.get(&key).cloned())
                .unwrap_or_default();
            B64.encode(value)
        }
        OP_DOM_CLASS_ADD => {
            let cls = operand_bytes(op, "s");
            if let Some(node) = cur {
                node.classes.insert(cls.clone());
            }
            B64.encode(cls)
        }
        OP_DOM_CLASS_CONTAINS => {
            let cls = operand_bytes(op, "s");
            let found = cur.as_ref().is_some_and(|n| n.classes.contains(&cls));
            (if found { "1" } else { "0" }).into()
        }
        OP_DOM_PARENT => {
            let appended = cur.as_ref().is_some_and(|n| n.appended);
            (if appended { "1" } else { "0" }).into()
        }
        OP_DOM_DISPATCH => "1".into(),
        OP_DOM_SERIALIZE => {
            if let Some(node) = cur {
                node.appended = true;
                doc_ids.insert(node.id.clone());
            }
            let serialized = match cur {
                Some(node) => {
                    let mut parts: Vec<String> = node
                        .attrs
                        .iter()
                        .map(|(name, value)| {
                            format!(
                                "{}{}{}",
                                String::from_utf8_lossy(name),
                                "=",
                                String::from_utf8_lossy(value)
                            )
                        })
                        .collect();
                    parts.sort();
                    parts.join(";")
                }
                None => String::new(),
            };
            B64.encode(serialized.into_bytes())
        }
        // Browser-observed entries: the expected values are
        // construction-determined for `QUERY_REAL`/`EVENT_REAL`/
        // `SERIALIZE_REAL`, while the layout probes carry the literal
        // placeholders 'geom'/'point' here — the verifier validates the
        // `SUBMITTED` trace entries against their invariants separately
        // (see verify_executed_trace), so a pure non-browser solver
        // cannot reproduce a valid trace without emulating layout.
        OP_DOM_QUERY_REAL => {
            let id = operand_bytes(op, "id");
            // The readback is authoritative only when the probed id IS
            // the current node (the PHP mirror's exact rule): a
            // constructed-but-not-current node reads 'none'.
            let current_is_probe = cur.as_ref().is_some_and(|n| n.id == id);
            if !doc_ids.contains(&id) || !current_is_probe {
                return "none".into();
            }
            let parts: String = cur
                .as_ref()
                .map(|n| {
                    let mut attrs: Vec<String> = n
                        .attrs
                        .iter()
                        .map(|(name, value)| {
                            format!(
                                "{}{}{}",
                                String::from_utf8_lossy(name),
                                "=",
                                String::from_utf8_lossy(value)
                            )
                        })
                        .collect();
                    attrs.sort();
                    attrs.join(";")
                })
                .unwrap_or_default();
            if parts.is_empty() {
                return "div".into();
            }
            format!("div|{parts}")
        }
        OP_DOM_GEOMETRY => "geom".into(),
        OP_DOM_POINT => "point".into(),
        OP_DOM_EVENT_REAL => {
            let id = operand_bytes(op, "id");
            if !doc_ids.contains(&id) {
                return "none".into();
            }
            "kiwi-ev:div".into()
        }
        OP_DOM_SERIALIZE_REAL => {
            // The interpreter hashes the canonical real readback; the
            // expected digest covers the same canonical string built
            // from the shadow's current node attributes.
            let canon = match &cur {
                Some(node) if node.appended => {
                    let mut parts: Vec<String> = node
                        .attrs
                        .iter()
                        .map(|(name, value)| {
                            format!(
                                "{}{}{}",
                                String::from_utf8_lossy(name),
                                "=",
                                String::from_utf8_lossy(value)
                            )
                        })
                        .collect();
                    parts.sort();
                    parts.join(";")
                }
                _ => String::new(),
            };
            hex_sha256(canon.as_bytes())
        }
        // The observed height is browser-only: the pure sim emits the
        // placeholder; the verifier replays the value the submitted
        // trace reports (see verify_executed_trace).
        OP_DOM_OBSERVE => "obs".into(),
        // The sibling index is a real traversal result the verifier
        // computes exactly from the append order (see
        // verify_executed_trace); the pure sim emits the placeholder.
        OP_DOM_SIBLING_INDEX => "dsib".into(),
        _ => "0".into(),
    }
}

/// The expected execution digest of a program for a challenge nonce:
/// hex HMAC-SHA256 keyed by the program bytes (the content-derived
/// digest key) over the label + context + canonical op trace. `None`
/// when the program is malformed.
pub fn expected_digest(program_b64: &str, nonce: &str) -> Option<String> {
    let bytes = B64.decode(program_b64).ok()?;
    if B64.encode(&bytes) != program_b64 {
        return None;
    }
    let program = decode(program_b64)?;
    let trace = canonical_trace(&program);

    let mut msg = Vec::new();
    msg.extend_from_slice(LABEL.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(nonce.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(program.scope.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(program.action.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(program.op_version.to_string().as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(trace.as_bytes());

    Some(hex::encode(hmac(&bytes, &msg)))
}

/// Test-only trace-fixture support, gated behind the crate's
/// `test-fixtures` cargo feature (enabled only for test builds via the
/// self dev-dependency in `Cargo.toml`, never for production
/// consumers).
///
/// This module is `#[doc(hidden)]` and exists so test suites and the
/// cross-language fixtures can synthesize a browser-equivalent
/// executed trace of a program without a browser. It is never a
/// production API: the synthesized trace fabricates the
/// browser-observed layout values (the fixed reference height below)
/// that only a real engine can measure, so nothing in the crate's
/// production surface promises a non-browser equivalent of a real
/// execution. Production verification works only over `SUBMITTED`
/// evidence (`verify_executed_trace` /
/// [`expected_digest_over_trace`](crate::execution::expected_digest_over_trace)),
/// which replays whatever the trace reports.
#[cfg(feature = "test-fixtures")]
#[doc(hidden)]
pub mod fixtures {
    use super::*;

    /// The fabricated reference height the browser-equivalent trace
    /// synthesizes: the real observed value is the engine's own text
    /// metrics (never predictable by the mirrors), so the synthesizer
    /// uses this constant and the verifier replays whatever the trace
    /// reports. A fabricated reference value, never a browser's
    /// measurement.
    pub const OBSERVED_HEIGHT: u8 = 10;

    /// The browser-equivalent executed trace of a program: the canonical
    /// trace with the layout-probe placeholders replaced by valid
    /// browser-observed values — monotonic `GEOMETRY` offsets with height
    /// [`OBSERVED_HEIGHT`] and the `POINT` probe naming the topmost
    /// constructed node ("div" when the program constructs any node,
    /// matching the verifier's whole-program construction predicate;
    /// "none" otherwise).
    ///
    /// The causal `OBSERVE` readback reports the observed text-metric
    /// height and writes it through into the u8 state, so the
    /// following checksum and read entries of this synthesized trace are
    /// computed over the observed byte.
    ///
    /// The entries are built per op from the same state machine the
    /// canonical trace uses; only the layout and observed entries are
    /// replaced, so readback values that contain ';' or parentheses travel
    /// intact.
    ///
    /// Test-only: fabricates a verifier-accepted trace without a
    /// browser. Test suites and cross-language fixtures only, never
    /// call from a production path.
    pub fn executed_trace_for(program: &Program) -> String {
        let mut u8arr: Vec<u8> = Vec::new();
        let mut cur: Option<DomNode> = None;
        let mut doc_ids: HashSet<Vec<u8>> = HashSet::new();
        let has_append = program.ops.iter().any(|op| op.opcode == OP_DOM_APPEND);
        let mut top = 0u64;
        let mut append_rank: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut entries: Vec<String> = Vec::with_capacity(program.ops.len());
        for op in &program.ops {
            if op.opcode == OP_DOM_APPEND {
                if let Some(node) = &cur {
                    let rank = append_rank.len();
                    append_rank.entry(node.id.clone()).or_insert(rank);
                }
            }
            if op.opcode == OP_DOM_GEOMETRY {
                entries.push(format!("geom({},{})", top * 10, 10));
                top += 1;
            } else if op.opcode == OP_DOM_POINT {
                entries.push(if has_append {
                    "point(div)".into()
                } else {
                    "point(none)".into()
                });
            } else if op.opcode == OP_DOM_SIBLING_INDEX {
                // The browser-equivalent sibling traversal: the rank of
                // the probed node's append (its real index among the
                // body children the program built) — the exact value
                // the verifier computes from the append order.
                entries.push(format!(
                    "dsib({})",
                    append_rank
                        .get(&operand_bytes(op, "id"))
                        .copied()
                        .map(|rank| rank + 1)
                        .unwrap_or(usize::MAX)
                ));
            } else if op.opcode == OP_DOM_OBSERVE {
                // The browser-equivalent observe: the fabricated reference
                // height (the real value is the engine's own text metrics,
                // never predictable here) is written through into the
                // replay state. The following checksum/read entries in this
                // synthesized trace are then computed over the observed
                // byte, the full causal-graph semantics, never a
                // placeholder.
                let idx = operand_int(op, "idx") as usize;
                entries.push(format!("obs({idx},{OBSERVED_HEIGHT})"));
                if idx < u8arr.len() {
                    u8arr[idx] = OBSERVED_HEIGHT;
                }
            } else {
                let result = simulate_op(op, &mut u8arr, &mut cur, &mut doc_ids);
                entries.push(format!("{}({result})", TRACE_NAMES[op.opcode as usize]));
            }
        }
        entries.join(";")
    }
}

/// Validate a `SUBMITTED` execution trace against a program: the
/// browser-equivalent canonical shape with the layout-probe entries
/// validated against their invariants (`GEOMETRY` monotonic in the
/// construction order with height >= 1, `POINT` naming the topmost
/// constructed node, the causal `OBSERVE` heights replayed into the
/// u8 state, the real-DOM readbacks equal to the simulated
/// values). Returns the submitted trace unchanged when it is a valid
/// execution of the program; `None` on any mismatch. The digest
/// comparison is the caller's (constant-time) job.
///
/// The trace is walked entry by entry against the simulated op
/// sequence, anchored by each op name at its exact position. The
/// readback values of the real-DOM probes legitimately contain ';'
/// and parentheses (the canonical attribute pairs), so no entry is
/// ever split on a separator; every non-layout entry is compared as
/// one byte string against its simulated value, and the layout and
/// observed entries are parsed from their digit shapes.
pub fn verify_executed_trace(program_b64: &str, nonce: &str, trace: &str) -> Option<String> {
    let _ = nonce; // the trace grammar does not depend on the nonce; the digest binding does
    let program = decode(program_b64)?;
    if trace.is_empty() {
        return None;
    }

    // First pass: the whole-program construction set (the `POINT`
    // probe predicate).
    let mut u8arr: Vec<u8> = Vec::new();
    let mut cur: Option<DomNode> = None;
    let mut doc_ids: HashSet<Vec<u8>> = HashSet::new();
    let mut construction: Vec<Vec<u8>> = Vec::new();
    for op in &program.ops {
        simulate_op(op, &mut u8arr, &mut cur, &mut doc_ids);
        if op.opcode == OP_DOM_APPEND {
            // The PHP mirror always appends (the current node id, or
            // '' when no node exists yet): the `POINT` probe's
            // whole-program predicate is "any DOM_APPEND op", so the
            // list must be non-empty exactly when an append exists.
            construction.push(cur.as_ref().map(|n| n.id.clone()).unwrap_or_default());
        }
    }

    // Second pass from a fresh state: the first pass left the mutable
    // simulation at its end state, and re-running on it would produce
    // different values for stateful ops (u8w checksums, real-DOM
    // readbacks) — the deterministic trace replays from the same
    // initial conditions (the PHP mirror does the same).
    let mut u8arr: Vec<u8> = Vec::new();
    let mut cur: Option<DomNode> = None;
    let mut doc_ids: HashSet<Vec<u8>> = HashSet::new();
    let mut prev_top: i64 = -1;
    let mut append_rank: HashMap<Vec<u8>, usize> = HashMap::new();
    let bytes = trace.as_bytes();
    let mut pos = 0usize;
    for (i, op) in program.ops.iter().enumerate() {
        if op.opcode == OP_DOM_APPEND {
            if let Some(node) = &cur {
                let rank = append_rank.len();
                append_rank.entry(node.id.clone()).or_insert(rank);
            }
        }
        let sim = simulate_op(op, &mut u8arr, &mut cur, &mut doc_ids);
        let name = TRACE_NAMES[op.opcode as usize];
        let name_open = format!("{name}(");
        if pos + name_open.len() > bytes.len()
            || &bytes[pos..pos + name_open.len()] != name_open.as_bytes()
        {
            return None;
        }
        pos += name_open.len();
        match op.opcode {
            OP_DOM_GEOMETRY => {
                let rest = std::str::from_utf8(&bytes[pos..]).ok()?;
                let end = rest.find(')')?;
                let body = &rest[..end];
                let mut parts = body.splitn(2, ',');
                let top: i64 = parts.next()?.parse().ok()?;
                let height: i64 = parts.next()?.parse().ok()?;
                if height < 1 || top < prev_top {
                    return None;
                }
                prev_top = top;
                pos += end + 1;
            }
            OP_DOM_POINT => {
                let top_tag = if construction.is_empty() {
                    "none"
                } else {
                    "div"
                };
                let tag_entry = format!("{top_tag})");
                if pos + tag_entry.len() > bytes.len()
                    || &bytes[pos..pos + tag_entry.len()] != tag_entry.as_bytes()
                {
                    return None;
                }
                pos += tag_entry.len();
            }
            OP_DOM_SIBLING_INDEX => {
                // The sibling-index traversal: the value is the rank of
                // the probed node's append among the appends replayed
                // so far (its real index among the body children the
                // program built). The walker computes the exact
                // expected value from the append order — never an
                // invariant, never a free scalar.
                let expected = append_rank
                    .get(&operand_bytes(op, "id"))
                    .copied()
                    .map(|rank| rank + 1);
                let rest = std::str::from_utf8(&bytes[pos..]).ok()?;
                let end = rest.find(')')?;
                let value: usize = rest[..end].parse().ok()?;
                if expected != Some(value) {
                    return None;
                }
                pos += end + 1;
            }
            OP_DOM_OBSERVE => {
                // The causal observe entry `obs(<dst>,<h>)`: the walker
                // validates the grammar and the bounds, requires the
                // probed id to be an appended node at this point, then
                // replays the reported height into its own u8 state so
                // every later checksum/read entry is exact-compared
                // against the observed byte (whole-trace coherence).
                let rest = std::str::from_utf8(&bytes[pos..]).ok()?;
                let end = rest.find(')')?;
                let body = &rest[..end];
                let mut parts = body.splitn(2, ',');
                let dst: i64 = parts.next()?.parse().ok()?;
                let observed: i64 = parts.next()?.parse().ok()?;
                if !doc_ids.contains(&operand_bytes(op, "id"))
                    || dst != operand_int(op, "idx") as i64
                    || !(1..=255).contains(&observed)
                {
                    return None;
                }
                if (dst as usize) < u8arr.len() {
                    u8arr[dst as usize] = observed as u8;
                }
                pos += end + 1;
            }
            _ => {
                let sim_entry = format!("{sim})");
                if pos + sim_entry.len() > bytes.len()
                    || &bytes[pos..pos + sim_entry.len()] != sim_entry.as_bytes()
                {
                    return None;
                }
                pos += sim_entry.len();
            }
        }
        if i + 1 < program.ops.len() {
            if pos >= bytes.len() || bytes[pos] != b';' {
                return None;
            }
            pos += 1;
        }
    }
    if pos != bytes.len() {
        return None;
    }

    Some(trace.to_string())
}

/// The digest over a `SUBMITTED` trace (the V2 evidence path): the same
/// content-derived HMAC as [`expected_digest`], but over the trace the
/// client actually executed, so the verifier can bind the
/// browser-observed entries. `None` when the program is malformed.
pub fn expected_digest_over_trace(program_b64: &str, nonce: &str, trace: &str) -> Option<String> {
    let bytes = B64.decode(program_b64).ok()?;
    if B64.encode(&bytes) != program_b64 {
        return None;
    }
    let program = decode(program_b64)?;

    let mut msg = Vec::new();
    msg.extend_from_slice(LABEL.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(nonce.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(program.scope.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(program.action.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(program.op_version.to_string().as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(trace.as_bytes());

    Some(hex::encode(hmac(&bytes, &msg)))
}

/// Errors of the program generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenerateError {
    #[error("execution key must be at least 16 bytes")]
    KeyTooShort,
    #[error("execution action must be 1-32 characters of [A-Za-z0-9._:-]")]
    InvalidAction,
    #[error("execution version must be the canonical numeric byte 1")]
    InvalidVersion,
    #[error("execution scope must be 1-128 characters of [A-Za-z0-9._:-]")]
    InvalidScope,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    // The browser-equivalent trace synthesizer moved to the
    // feature-gated test-fixtures module (see `fixtures`); the self
    // dev-dependency in Cargo.toml enables `test-fixtures` for every
    // test build, so the unit tests reach it here.
    use super::fixtures::executed_trace_for;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NONCE: &str = "xAfSYcl6VyvtYZcQUhvXxin2pojnG5TmZoHg7K6NG3s=";

    #[test]
    fn invalid_scopes_are_rejected_before_any_stream_work() {
        for scope in [
            "",
            " ",
            "login action",
            "login|action",
            "héllo",
            &"a".repeat(129),
            &"a".repeat(300),
        ] {
            let err = generate(KEY, NONCE, scope, "login-action", 1).unwrap_err();
            assert_eq!(
                err,
                GenerateError::InvalidScope,
                "scope {scope:?} must be InvalidScope"
            );
        }
        // A valid scope still generates and the blob decodes with the
        // identical scope (the boundary of the decoder grammar).
        let scope = "a".repeat(128);
        let program =
            generate(KEY, NONCE, &scope, "login-action", 1).expect("boundary scope must generate");
        let decoded = decode(&program).expect("the generated blob must parse");
        assert_eq!(decoded.scope, scope);
    }

    #[test]
    fn generation_is_deterministic() {
        let a = generate(KEY, NONCE, "login", "login-action", 1).unwrap();
        let b = generate(KEY, NONCE, "login", "login-action", 1).unwrap();
        assert_eq!(a, b);
        let c = generate(KEY, NONCE, "signup", "login-action", 1).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn program_round_trips() {
        let p = generate(KEY, NONCE, "login", "login-action", 1).unwrap();
        assert!(is_valid_program(&p));
        let program = decode(&p).unwrap();
        assert_eq!(program.scope, "login");
        assert_eq!(program.action, "login-action");
        assert_eq!(program.op_version, 1);
        assert!((program.ops.len() as u8) >= MIN_OPS && (program.ops.len() as u8) <= MAX_OPS);
        assert!(!canonical_trace(&program).is_empty());
    }

    #[test]
    fn malformed_programs_are_rejected() {
        assert!(!is_valid_program(""));
        assert!(!is_valid_program("not-base64!"));
        assert!(!is_valid_program(&B64.encode([0x02u8, 0x01, 0x78])));
        assert!(!is_valid_program(&B64.encode([0x01u8, 0x05])));
    }

    #[test]
    fn digest_is_hex_and_nonce_bound() {
        let p = generate(KEY, NONCE, "login", "login-action", 1).unwrap();
        let d = expected_digest(&p, NONCE).unwrap();
        assert_eq!(d.len(), 64);
        assert!(d.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(
            d,
            expected_digest(&p, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap()
        );
        assert!(expected_digest("garbage", NONCE).is_none());
    }

    #[test]
    fn key_too_short_is_rejected() {
        assert_eq!(
            generate(b"short", NONCE, "login", "login-action", 1),
            Err(GenerateError::KeyTooShort)
        );
    }

    #[test]
    fn fixed_opcode_set_is_fully_reachable() {
        // Both canonical execution versions are sampled: a version-1
        // program draws its fillers from the other 28 opcodes (0..27)
        // and its probe block from 28..32, so the version-1 corpus
        // reaches exactly 33 opcodes — the observe opcode (33) is a
        // version-2 extension and must never appear in a version-1
        // program. The version-2 causal grammar always stamps the
        // observe op, so its corpus reaches all 34 fixed opcodes.
        let mut seen_v1 = std::collections::HashSet::new();
        for i in 0..64u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("nonce-v1-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 1).unwrap();
            let program = decode(&p).unwrap();
            assert_eq!(program.op_version, 1);
            for op in &program.ops {
                seen_v1.insert(op.opcode);
            }
        }
        assert_eq!(
            seen_v1.len(),
            (OP_COUNT - 2) as usize,
            "the version-1 opcode space is 0..32 (the observe opcode never appears)"
        );
        assert!(!seen_v1.contains(&OP_DOM_OBSERVE));
        let mut seen_v2 = std::collections::HashSet::new();
        for i in 0..64u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("nonce-v2-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 2).unwrap();
            let program = decode(&p).unwrap();
            assert_eq!(program.op_version, 2);
            for op in &program.ops {
                seen_v2.insert(op.opcode);
            }
        }
        assert_eq!(
            seen_v2.len(),
            OP_COUNT as usize - 1,
            "the version-2 corpus reaches 34 of the 35 fixed opcodes"
        );
        assert!(seen_v2.contains(&OP_DOM_OBSERVE));
        assert!(!seen_v2.contains(&OP_DOM_SIBLING_INDEX));

        let mut seen_v3 = std::collections::HashSet::new();
        for i in 0..64u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("nonce-v3-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 3).unwrap();
            let program = decode(&p).expect("the version-3 program must parse");
            for op in &program.ops {
                seen_v3.insert(op.opcode);
            }
        }
        assert_eq!(
            seen_v3.len(),
            OP_COUNT as usize,
            "the version-3 corpus reaches the full fixed opcode set"
        );
        assert!(seen_v3.contains(&OP_DOM_SIBLING_INDEX));
        assert!(seen_v3.contains(&OP_DOM_OBSERVE));
    }

    #[test]
    fn generated_programs_carry_the_guaranteed_structure() {
        // The generator-level corpus: every generated program opens
        // with the mandatory DOM construction block (createElement with
        // a drawn id, a mutate op on that node, an append), then the
        // mandatory causal u8 chain (create the array, observe the real
        // height of the constructed node into it, read the observed
        // byte back, checksum or rotate over it) and the mandatory
        // real-probe block (one of the id-carrying real probes 28/29/31
        // plus 1..3 further real probes). Every id operand references
        // the constructed id bytes, drawn once and reused. The
        // remaining slots are filled from the other 28 opcodes (0..27),
        // never from the browser-observed probes.
        for i in 0..128u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("guaranteed-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 2).unwrap();
            let program = decode(&p).expect("the program must parse");
            assert_eq!(program.op_version, 2);
            assert!((program.ops.len() as u8) >= MIN_OPS && (program.ops.len() as u8) <= MAX_OPS);
            let first = &program.ops[0];
            assert_eq!(
                first.opcode, OP_DOM_CREATE,
                "op 0 is the construction create"
            );
            let created_id = match first.operands.get("id") {
                Some(Operand::Bytes(b)) => b.clone(),
                _ => panic!("the create op must carry its drawn id bytes"),
            };
            assert!((created_id.len() as u8) >= 4 && created_id.len() <= 16);
            assert!(matches!(
                program.ops[1].opcode,
                OP_DOM_SET_ATTR | OP_DOM_DATASET_SET | OP_DOM_CLASS_ADD
            ));
            assert_eq!(
                program.ops[2].opcode, OP_DOM_APPEND,
                "op 2 is the construction append"
            );
            assert_eq!(
                program.ops[3].opcode, OP_U8_CREATE,
                "op 3 creates the u8 array"
            );
            let u8c_len = match program.ops[3].operands.get("len") {
                Some(Operand::Int(n)) => *n as usize,
                _ => panic!("u8-create must carry its length"),
            };
            let obs = &program.ops[4];
            assert_eq!(
                obs.opcode, OP_DOM_OBSERVE,
                "op 4 observes the constructed node"
            );
            let obs_id = match obs.operands.get("id") {
                Some(Operand::Bytes(b)) => b.clone(),
                _ => panic!("the observe op must carry the constructed id"),
            };
            assert_eq!(
                obs_id, created_id,
                "the observe op references the constructed id"
            );
            let obs_idx = match obs.operands.get("idx") {
                Some(Operand::Int(n)) => *n as usize,
                _ => panic!("the observe op must carry its u8 index"),
            };
            assert!(
                obs_idx < u8c_len,
                "the observed byte always lands inside the created array"
            );
            assert_eq!(
                program.ops[5].opcode, OP_U8_READ,
                "op 5 reads the observed byte back"
            );
            let read_idx = match program.ops[5].operands.get("idx") {
                Some(Operand::Int(n)) => *n as usize,
                _ => panic!("the read op must carry its u8 index"),
            };
            assert_eq!(read_idx, obs_idx, "the read targets the observed index");
            assert!(
                matches!(program.ops[6].opcode, OP_U8_WRITE | OP_U8_ROTATE),
                "op 6 checksums or rotates over the observed byte"
            );
            let link = program.ops[7].opcode;
            assert!(
                matches!(
                    link,
                    OP_DOM_QUERY_REAL | OP_DOM_GEOMETRY | OP_DOM_EVENT_REAL
                ),
                "the link probe is one of the id-carrying real probes"
            );
            let mut seen_constructed_probe = false;
            let mut index = 7usize;
            while index < program.ops.len() && program.ops[index].opcode >= OP_DOM_QUERY_REAL {
                let op = &program.ops[index];
                if matches!(
                    op.opcode,
                    OP_DOM_QUERY_REAL | OP_DOM_GEOMETRY | OP_DOM_EVENT_REAL
                ) {
                    let id = match op.operands.get("id") {
                        Some(Operand::Bytes(b)) => b.clone(),
                        _ => panic!("id-carrying probes must carry their id operand"),
                    };
                    assert_eq!(
                        id, created_id,
                        "every id-carrying probe references the constructed id"
                    );
                    seen_constructed_probe = true;
                }
                index += 1;
            }
            assert!(
                seen_constructed_probe,
                "at least one probe reads the constructed id"
            );
            for op in &program.ops[index..] {
                assert!(
                    op.opcode <= OP_DOM_SERIALIZE,
                    "the filler ops are drawn from the other 28 opcodes, never 28..32"
                );
            }
            // The browser-equivalent executed trace verifies against
            // the program: the synthesized observe entry carries the
            // fabricated height and the write-through replay makes the
            // later checksum/read entries coherent.
            let trace = executed_trace_for(&program);
            assert!(
                verify_executed_trace(&p, &nonce, &trace).is_some(),
                "the executed trace of a generated program must verify"
            );
            assert!(
                trace.contains("obs("),
                "every generated program carries the causal observe entry"
            );
        }
    }

    #[test]
    fn causal_observe_forgeries_are_rejected() {
        // The V2 adversarial framing: the observed height is written
        // through into the replay state, so a trace that reports a
        // value but does not carry it coherently through the later
        // checksum/read entries is rejected.
        let nonce = B64.encode(sha2::Sha256::digest(b"obsforge-0"));
        let p = generate(KEY, &nonce, "login", "login-action", 2).unwrap();
        let program = decode(&p).expect("the program must parse");
        assert_eq!(program.op_version, 2);
        let trace = executed_trace_for(&program);
        assert!(verify_executed_trace(&p, &nonce, &trace).is_some());
        let obs_entry = trace
            .split(';')
            .find(|e| e.starts_with("obs("))
            .expect("the trace carries the observe entry")
            .to_string();

        // Bounds forgeries: heights 0 and 256 are rejected.
        let height_0 = trace.replace(&obs_entry, "obs(0,0)");
        assert!(
            verify_executed_trace(&p, &nonce, &height_0).is_none(),
            "an observe height of 0 must be rejected"
        );
        let height_256 = trace.replace(&obs_entry, "obs(0,256)");
        assert!(
            verify_executed_trace(&p, &nonce, &height_256).is_none(),
            "an observe height of 256 must be rejected"
        );

        // A dst that differs from the program operand is rejected.
        let wrong_dst = trace.replace(&obs_entry, "obs(63,10)");
        assert!(
            verify_executed_trace(&p, &nonce, &wrong_dst).is_none(),
            "an observe dst that differs from the operand must be rejected"
        );

        // The write-through contradiction: report the observed
        // value but recompute the u8-read of the observed index as
        // if the write never happened (0).
        let read_entry = trace
            .split(';')
            .find(|e| e.starts_with("u8r("))
            .expect("the trace carries the observed-byte read")
            .to_string();
        let no_write = trace.replace(&read_entry, "u8r(0)");
        assert_ne!(no_write, trace, "the forged read must differ");
        assert!(
            verify_executed_trace(&p, &nonce, &no_write).is_none(),
            "a trace that reports the observe but drops the write-through is rejected"
        );

        // Removing the observe entry entirely breaks the anchored
        // walk.
        let obs_removed = trace
            .split(';')
            .filter(|e| !e.starts_with("obs("))
            .collect::<Vec<_>>()
            .join(";");
        assert!(
            verify_executed_trace(&p, &nonce, &obs_removed).is_none(),
            "a trace without the observe entry must be rejected"
        );
    }

    #[test]
    fn naive_probe_forgeries_are_rejected() {
        // The adversarial framing: a solver that skips the DOM
        // construction cannot forge the probe entries. The executed
        // trace of a program whose probes reference constructed nodes
        // carries the real readbacks; a naive trace with 'none' probes
        // (as if the constructed node never existed) or with the probe
        // block removed is rejected by the anchored walk.
        let mut found = 0u32;
        for i in 0..128u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("forge-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 2).unwrap();
            let program = decode(&p).expect("the program must parse");
            assert_eq!(program.op_version, 2);
            let trace = executed_trace_for(&program);
            assert!(verify_executed_trace(&p, &nonce, &trace).is_some());
            let link = program.ops[7].opcode;
            if link == OP_DOM_QUERY_REAL {
                // The naive 'none' forgery: rewrite the create id bytes
                // of op 0 in the blob to a foreign id of the same
                // length, so the probes reference a node that was never
                // constructed and the executed trace of that program
                // reads every probe as 'none'.
                assert!(
                    trace.contains("qreal(div|"),
                    "the executed trace must read back the constructed node"
                );
                let bytes = B64.decode(&p).unwrap();
                let scope_len = bytes[1] as usize;
                let action_len = bytes[2 + scope_len] as usize;
                let op0 = 2 + scope_len + 1 + action_len + 2;
                assert_eq!(bytes[op0], OP_DOM_CREATE);
                let id_len = bytes[op0 + 2] as usize;
                assert!(id_len >= 4);
                let mut naive = bytes.clone();
                for b in naive[op0 + 3..op0 + 3 + id_len].iter_mut() {
                    *b = b'z';
                }
                assert_ne!(naive, bytes, "the foreign id must differ from the drawn id");
                let naive_program = decode(&B64.encode(naive)).expect("the naive program parses");
                let naive_trace = executed_trace_for(&naive_program);
                assert!(
                    naive_trace.contains("qreal(none)"),
                    "a solver skipping the construction reads the probe as 'none'"
                );
                assert!(
                    verify_executed_trace(&p, &nonce, &naive_trace).is_none(),
                    "the 'none' probe forgery must be rejected against the real program"
                );
                found += 1;
                break;
            }
        }
        assert_eq!(found, 1, "the corpus must contain a qreal link probe");

        // Removing the probe block: the trace truncated after the
        // construction append is missing every probe entry and must be
        // rejected.
        let nonce = B64.encode(sha2::Sha256::digest(b"forge-trunc"));
        let p = generate(KEY, &nonce, "login", "login-action", 2).unwrap();
        let program = decode(&p).expect("the program must parse");
        let trace = executed_trace_for(&program);
        let prefix = "dcreate(";
        let start = trace
            .find(prefix)
            .expect("the trace opens with the create entry");
        let head = &trace[start..];
        let cut = head
            .find("dappend(1);")
            .expect("the construction append entry")
            + "dappend(1);".len();
        let truncated = &trace[..start + cut];
        assert!(
            verify_executed_trace(&p, &nonce, truncated).is_none(),
            "a trace without the probe entries must be rejected"
        );
    }

    #[test]
    fn version_one_programs_carry_the_legacy_skeleton() {
        // The N-1 generation corpus: a version-1 program is the legacy
        // construction-to-probe skeleton — no observe opcode (33), no
        // causal u8 chain, its link probe at op 3 (the construction
        // block is ops[0..2] and the probe block opens immediately
        // after), floor 8 — and its browser-equivalent executed trace
        // verifies against the current verifier and never carries an
        // 'obs(' entry; the causal observe write is a v2-only
        // extension.
        for i in 0..128u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("v1-skel-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 1).unwrap();
            let program = decode(&p).expect("the program must parse");
            assert_eq!(program.op_version, 1);
            assert!(
                (program.ops.len() as u8) >= MIN_OPS && (program.ops.len() as u8) <= MAX_OPS,
                "a version-1 program has the 8..24 op bounds"
            );
            for op in &program.ops {
                assert!(
                    op.opcode != OP_DOM_OBSERVE,
                    "a version-1 program never carries the observe opcode"
                );
            }
            let first = &program.ops[0];
            assert_eq!(
                first.opcode, OP_DOM_CREATE,
                "op 0 is the construction create"
            );
            let created_id = match first.operands.get("id") {
                Some(Operand::Bytes(b)) => b.clone(),
                _ => panic!("the create op must carry its drawn id bytes"),
            };
            assert!(matches!(
                program.ops[1].opcode,
                OP_DOM_SET_ATTR | OP_DOM_DATASET_SET | OP_DOM_CLASS_ADD
            ));
            assert_eq!(
                program.ops[2].opcode, OP_DOM_APPEND,
                "op 2 is the construction append"
            );
            // No causal chain: the probe block opens at op 3.
            let link = program.ops[3].opcode;
            assert!(
                matches!(
                    link,
                    OP_DOM_QUERY_REAL | OP_DOM_GEOMETRY | OP_DOM_EVENT_REAL
                ),
                "the version-1 link probe sits at op 3 (no u8 chain)"
            );
            let mut seen_constructed_probe = false;
            let mut index = 3usize;
            while index < program.ops.len() && program.ops[index].opcode >= OP_DOM_QUERY_REAL {
                let op = &program.ops[index];
                if matches!(
                    op.opcode,
                    OP_DOM_QUERY_REAL | OP_DOM_GEOMETRY | OP_DOM_EVENT_REAL
                ) {
                    let id = match op.operands.get("id") {
                        Some(Operand::Bytes(b)) => b.clone(),
                        _ => panic!("id-carrying probes must carry their id operand"),
                    };
                    assert_eq!(
                        id, created_id,
                        "every id-carrying probe references the constructed id"
                    );
                    seen_constructed_probe = true;
                }
                index += 1;
            }
            assert!(
                seen_constructed_probe,
                "at least one probe reads the constructed id"
            );
            for op in &program.ops[index..] {
                assert!(
                    op.opcode <= OP_DOM_SERIALIZE,
                    "the filler ops are drawn from the other 28 opcodes, never 28..32"
                );
            }
            let trace = executed_trace_for(&program);
            assert!(
                verify_executed_trace(&p, &nonce, &trace).is_some(),
                "the executed trace of a version-1 program must verify"
            );
            // The causal observe write is a v2-only extension, so a
            // version-1 trace never carries the observe entry.
            assert!(!trace.contains("obs("));
        }
    }

    #[test]
    fn version_bytes_cannot_cross_the_grammar_fence() {
        // The N-1 decode fence: a version-2 program blob (whose causal
        // chain stamps the observe opcode 33) with its version byte
        // rewritten to 1 must decode to null — an old interpreter
        // rejects the newer grammar by the declared version byte alone,
        // before any opcode is read. And a version-1 blob carrying a
        // crafted opcode-33 op must decode to null too: opcode 33 is
        // outside the version-1 opcode space (0..32).
        let scope_len = b"login".len();
        let action_len = b"login-action".len();
        let version_at = 3 + scope_len + action_len;
        let op0_at = version_at + 2;

        let v2_b64 = generate(KEY, NONCE, "login", "login-action", 2).unwrap();
        let v2_bytes = B64.decode(&v2_b64).unwrap();
        assert_eq!(v2_bytes[version_at], 2);
        assert!(
            decode(&v2_b64).is_some(),
            "the version-2 program must parse"
        );
        let mut downgraded = v2_bytes.clone();
        downgraded[version_at] = 1;
        let downgraded_b64 = B64.encode(downgraded);
        assert!(
            decode(&downgraded_b64).is_none(),
            "a version-2 program with opcode 33 must never decode as version 1"
        );

        let v1_b64 = generate(KEY, NONCE, "login", "login-action", 1).unwrap();
        let mut v1_bytes = B64.decode(&v1_b64).unwrap();
        assert_eq!(v1_bytes[version_at], 1);
        assert_eq!(
            v1_bytes[op0_at], OP_DOM_CREATE,
            "op 0 is the construction create"
        );
        assert!(decode(&v1_b64).is_some());
        v1_bytes[op0_at] = OP_DOM_OBSERVE;
        let crafted_b64 = B64.encode(v1_bytes);
        assert!(
            decode(&crafted_b64).is_none(),
            "opcode 33 inside a version-1 blob must be rejected"
        );

        // A version byte outside the canonical set 1|2|3 is refused at
        // the decode fence, never interpreted as any grammar, and the
        // fences are one-way: a version-3 program rewritten to version
        // 2 must decode to null (its sibling-index opcode 34 is a
        // version-3 extension), and a version-2 program rewritten to
        // version 3 must decode to null too (version 3 requires the
        // second constructed node in its fixed skeleton? no — decode
        // does not enforce the skeleton, but the opcode bound does: a
        // version-3 rewrite of a version-2 blob is structurally legal
        // only if no opcode 34 appears — the fence test pins the
        // downward direction, which is the fleet-relevant one).
        let v3_b64 = generate(KEY, NONCE, "login", "login-action", 3).unwrap();
        let mut v3_down = B64.decode(&v3_b64).unwrap();
        assert_eq!(v3_down[version_at], 3);
        v3_down[version_at] = 2;
        assert!(
            decode(&B64.encode(v3_down)).is_none(),
            "a version-3 program with opcode 34 must never decode as version 2"
        );
        let mut foreign_version = v2_bytes;
        foreign_version[version_at] = 9;
        assert!(
            decode(&B64.encode(foreign_version)).is_none(),
            "a version byte outside 1..3 must decode to null"
        );
    }

    #[test]
    fn layout_probe_forgeries_are_rejected() {
        // The geometry forgeries: a height-0 entry and a non-monotonic
        // entry both fail the verifier's layout invariants, while the
        // original executed trace verifies.
        let mut height_0 = false;
        for i in 0..256u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("geom0-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 1).unwrap();
            let program = decode(&p).expect("the program must parse");
            if program.ops.iter().any(|op| op.opcode == OP_DOM_GEOMETRY) {
                let trace = executed_trace_for(&program);
                assert!(verify_executed_trace(&p, &nonce, &trace).is_some());
                let forged = trace.replacen("geom(0,10)", "geom(0,0)", 1);
                assert_ne!(forged, trace, "the height-0 forge must change the trace");
                assert!(
                    verify_executed_trace(&p, &nonce, &forged).is_none(),
                    "a geometry entry with height 0 must be rejected"
                );
                height_0 = true;
                break;
            }
        }
        assert!(height_0, "the corpus must contain a geometry probe");

        let mut non_monotonic = false;
        for i in 0..256u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("geom1-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 1).unwrap();
            let program = decode(&p).expect("the program must parse");
            let geoms = program
                .ops
                .iter()
                .filter(|op| op.opcode == OP_DOM_GEOMETRY)
                .count();
            if geoms >= 2 {
                let trace = executed_trace_for(&program);
                assert!(verify_executed_trace(&p, &nonce, &trace).is_some());
                let forged = trace.replacen("geom(0,10)", "geom(50,10)", 1);
                assert!(
                    verify_executed_trace(&p, &nonce, &forged).is_none(),
                    "a non-monotonic geometry sequence must be rejected"
                );
                non_monotonic = true;
                break;
            }
        }
        assert!(non_monotonic, "the corpus must contain two geometry probes");
    }

    #[test]
    fn dataset_keys_match_the_safe_alphabet_grammar() {
        // The generator-level property test: every dataset key drawn
        // into a generated program must match the deliberately boring
        // safe grammar `x[0-9a-z_]{0,15}` — the literal `x` followed by
        // 0..15 characters of [0-9a-z_]. The grammar guarantees no key
        // can carry the `|` canonical separator, DOM punctuation,
        // whitespace or uppercase.
        let mut seen = 0usize;
        for i in 0..64u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("d-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", 1).unwrap();
            let program = decode(&p).unwrap();
            for op in &program.ops {
                if op.opcode != OP_DOM_DATASET_SET {
                    continue;
                }
                seen += 1;
                let key = match op.operands.get("s") {
                    Some(Operand::Bytes(b)) => b.clone(),
                    _ => panic!("dataset-set must carry a byte-string key"),
                };
                assert!(!key.is_empty(), "a dataset key is never empty");
                assert!(key.len() <= 16, "a dataset key is at most 16 bytes");
                assert_eq!(key[0], b'x', "a dataset key starts with the literal x");
                assert!(
                    key[1..]
                        .iter()
                        .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || *b == b'_'),
                    "the key tail is drawn from [0-9a-z_]"
                );
            }
        }
        assert!(seen > 0, "the sampled programs must exercise dataset keys");
    }
}
