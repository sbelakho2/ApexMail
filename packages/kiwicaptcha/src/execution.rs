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
//! 21 DOM_DATASET_SET key-length byte (1..16) + digit-first key + value-length + value
//! 22 DOM_DATASET_GET key-length byte + key bytes
//! 23 DOM_CLASS_ADD   class-length byte (1..12) + class bytes
//! 24 DOM_CLASS_CONTAINS class-length byte + class bytes
//! 25 DOM_PARENT    (no operands)
//! 26 DOM_DISPATCH  (no operands)
//! 27 DOM_SERIALIZE (no operands)
//! ```
//!
//! String literals are printable ASCII (0x20..0x7E); ids use the
//! standard-base64 alphabet; class names use `[A-Za-z0-9_-]` (never a
//! space); dataset keys always start with a digit (so a real-DOM
//! dataset write can never reflect onto a `data-*` attribute that
//! collides with the fixed attribute-name list). The operand grammar
//! mirrors the PHP generator byte-for-byte: the length bytes carry the
//! real length, never a raw PRF byte, except the raw-byte operands
//! (U8_CREATE, U8_WRITE, U8_READ, U8_ROTATE, int literals, tag/name indexes,
//! slice start/count), where both sides derive the same value from the
//! raw byte. All string semantics are byte-exact (the PHP mirror uses
//! raw bytes, so this crate stores operand strings as `Vec<u8>`).
//!
//! # The canonical op trace and the execution digest
//!
//! The canonical op trace is the deterministic execution trace: one
//! `opname(result)` entry per op, joined with ';'. Results are decimal
//! integers, "1"/"0", or standard base64 of a byte string — no result
//! alphabet contains '(', ')' or ';'. Both the server verifier and the
//! browser interpreter simulate the same deterministic state machine
//! (u8 array, current DOM node, appended-id set).
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

use std::collections::{BTreeMap, HashSet};

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
pub const OP_COUNT: u8 = 28;

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
/// same blob layout. The version is a canonical decimal u8 (the PHP
/// mirror casts the same string through `(int)` after the same
/// alphabet check, so both sides stamp the identical byte).
pub fn generate(
    execution_key: &[u8],
    nonce: &str,
    scope: &str,
    action: &str,
    version: &str,
) -> Result<String, GenerateError> {
    if execution_key.len() < 16 {
        return Err(GenerateError::KeyTooShort);
    }
    if !is_identifier(action, 32) {
        return Err(GenerateError::InvalidAction);
    }
    let op_version: u8 = version.parse().map_err(|_| GenerateError::InvalidVersion)?;

    let mut cursor = Cursor::new(prf_stream(execution_key, nonce, scope, action, version));

    let mut program = Vec::new();
    program.push(FORMAT_VERSION);
    program.push(scope.len() as u8);
    program.extend_from_slice(scope.as_bytes());
    program.push(action.len() as u8);
    program.extend_from_slice(action.as_bytes());
    program.push(op_version);
    let op_count = 8 + (cursor.next_byte() % 17);
    program.push(op_count);

    for _ in 0..op_count {
        let opcode = cursor.next_byte() % OP_COUNT;
        program.push(opcode);
        program.extend_from_slice(&draw_operands(&mut cursor, opcode));
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
            out.push(0x30 + (cursor.next_byte() % 10));
            for _ in 1..len {
                out.push(0x20 + (cursor.next_byte() % 0x5F));
            }
            out.extend_from_slice(&draw_value(cursor));
            out
        }
        OP_DOM_DATASET_GET => draw_string(cursor, 0),
        OP_DOM_CLASS_ADD | OP_DOM_CLASS_CONTAINS => draw_class(cursor),
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
    let action_len = cursor.take_strict(1)?[0] as usize;
    if action_len == 0 || action_len > 32 {
        return None;
    }
    let action = std::str::from_utf8(&cursor.take_strict(action_len)?)
        .ok()?
        .to_string();
    let op_version = cursor.take_strict(1)?[0];
    let op_count = cursor.take_strict(1)?[0];
    if !(MIN_OPS..=MAX_OPS).contains(&op_count) {
        return None;
    }

    let mut ops = Vec::with_capacity(op_count as usize);
    for _ in 0..op_count {
        let opcode = cursor.take_strict(1)?[0];
        if opcode >= OP_COUNT {
            return None;
        }
        ops.push(Op {
            opcode,
            operands: read_operands(&mut cursor, opcode)?,
        });
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

/// Errors of the program generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenerateError {
    #[error("execution key must be at least 16 bytes")]
    KeyTooShort,
    #[error("execution action must be 1-32 characters of [A-Za-z0-9._:-]")]
    InvalidAction,
    #[error("execution version must be a canonical decimal u8")]
    InvalidVersion,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NONCE: &str = "xAfSYcl6VyvtYZcQUhvXxin2pojnG5TmZoHg7K6NG3s=";

    #[test]
    fn generation_is_deterministic() {
        let a = generate(KEY, NONCE, "login", "login-action", "1").unwrap();
        let b = generate(KEY, NONCE, "login", "login-action", "1").unwrap();
        assert_eq!(a, b);
        let c = generate(KEY, NONCE, "signup", "login-action", "1").unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn program_round_trips() {
        let p = generate(KEY, NONCE, "login", "login-action", "1").unwrap();
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
        let p = generate(KEY, NONCE, "login", "login-action", "1").unwrap();
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
            generate(b"short", NONCE, "login", "login-action", "1"),
            Err(GenerateError::KeyTooShort)
        );
    }

    #[test]
    fn fixed_opcode_set_is_fully_reachable() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..64u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("nonce-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", "1").unwrap();
            let program = decode(&p).unwrap();
            for op in &program.ops {
                seen.insert(op.opcode);
            }
        }
        assert_eq!(seen.len(), OP_COUNT as usize);
    }

    #[test]
    fn trace_values_never_contain_separators() {
        for i in 0..16u32 {
            let nonce = B64.encode(sha2::Sha256::digest(format!("n-{i}").as_bytes()));
            let p = generate(KEY, &nonce, "login", "login-action", "1").unwrap();
            let program = decode(&p).unwrap();
            let trace = canonical_trace(&program);
            for entry in trace.split(';') {
                assert!(entry.ends_with(')'));
                assert!(entry.contains('('));
            }
        }
    }
}
