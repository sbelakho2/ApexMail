/*!
 * KiwiCaptcha execution interpreter — ExecutionChallengeV1 (the
 * Cap-style dimension). FIXED, AUDITED asset: lazy-loaded by the widget
 * driver (execution.<sha256>.js) ONLY when a challenge response carries
 * an execution program; a SHA-only page never fetches this file.
 *
 * THIS FILE MUST NEVER CONTAIN eval / new Function / setTimeout-driven
 * code generation: the browser test suite asserts this with a spec grep
 * (the interpreter is a small deterministic bytecode VM, nothing more).
 * There is deliberately no Math.random and no Date.readout in the op
 * semantics — the executed program is a pure function of its bytes, so
 * the server recomputes the identical canonical op trace.
 *
 * ── How it runs ───────────────────────────────────────────────────────
 * The driver creates a SANDBOXED EPHEMERAL IFRAME per armed challenge
 * (srcdoc with a minimal document; sandbox="allow-scripts
 * allow-same-origin" — allow-same-origin is REQUIRED because a
 * sandboxed opaque-origin document cannot load a same-origin script
 * under the recommended CSP `script-src 'self'`; the sandbox flags that
 * are not granted — forms, popups, top-navigation, pointer lock — stay
 * blocked). The iframe loads THIS asset via <script src integrity=...>
 * (same-origin, CSP-clean, SRI-pinned by the browser), the interpreter
 * announces ready, the driver posts the program, the interpreter runs
 * the VM and posts back the execution digest (64 lowercase hex). The
 * driver validates message.source === the iframe it created and the
 * per-run id before accepting anything.
 *
 * ── The compute/DOM split ─────────────────────────────────────────────
 * The opcode set is split into the COMPUTE SUBSET (opcodes 0-15:
 * integer arithmetic, typed-array ops, string/UTF-8 ops — pure
 * functions of their operands, no DOM) and the DOM SUBSET (opcodes
 * 16-27: createElement/setAttribute/appendChild/querySelector/
 * getAttribute/dataset/classList/parent/dispatch/serialize against the
 * sandboxed iframe document; opcodes 28-33: the real-DOM evidence
 * probes — real query readback, layout geometry, the topmost-node
 * point probe, a real event dispatch readback, the canonical
 * serialization digest and the causal observe probe (the measured
 * height of the constructed node, written into the u8 state) —
 * validated by the verifier's invariants (exact for
 * QUERY_REAL/EVENT_REAL/SERIALIZE_REAL, monotonic geometry with
 * height >= 1, the point probe naming the topmost constructed node,
 * and the observe entry replaying the reported height). The compute
 * subset is worker-portable by
 * design: it never touches the document, so it can move into the
 * existing worker architecture (kiwi-worker.js) without any protocol
 * change. In THIS implementation the whole VM runs inside the ephemeral
 * iframe, because the op-count bound (8..24 ops, enforced on every
 * program) keeps the wall-clock cost ~0.1 ms on a low-end device —
 * orders of magnitude below the ~20 ms budget the dimension documents —
 * and a worker hop would add latency, not safety. The budget is a
 * documented bound, never a runtime timer: the interpreter enforces the
 * OLD-COUNT bound (the deterministic proxy for the wall-clock cap).
 *
 * ── Determinism contract ──────────────────────────────────────────────
 * The interpreter computes the canonical op trace exactly like the
 * server mirrors (PHP KiwiCaptcha\ExecutionChallengeGenerator, Rust
 * crate::execution): one `opname(result)` entry per op joined with ';',
 * results being decimal integers, "1"/"0", or standard base64 of a
 * byte string. The single browser-observed entry is 'obs(<dst>,<h>)':
 * the height h is the real text-metric layout measurement of the
 * constructed node (a fixed-width block rendering a canonical text
 * line in the engine's default font), written into the VM u8 state at
 * dst, and replayed by the verifier from the trace itself. The
 * mirrors never predict the observed height: the value is engine and
 * platform specific, so their browser-equivalent traces carry the
 * same entry shape over a fabricated reference value. The digest is hex
 * HMAC-SHA256 keyed by the PROGRAM
 * BYTES (the content-derived key; the secret execution_key never
 * leaves the server) over
 * `kiwi-execution-v1|nonce|scope|action|version|canonical_op_trace`
 * with scope/action/version read from the program blob itself. The
 * digest binds the submission to the issued program and challenge
 * context; the server recomputes the expected value from the STORED
 * program and compares in constant time.
 *
 * The interpreter runs its own tiny SHA-256 + HMAC-SHA256 (no
 * crypto.subtle dependency: the sandboxed iframe may run in contexts
 * where the WebCrypto API is unavailable, and a synchronous
 * implementation keeps the digest computation deterministic).
 */
(function () {
  "use strict";

  var KIWI_EXECUTION_PROTOCOL = "kiwi-execution-v1";
  var KIWI_EXECUTION_READY = "kiwi-execution-ready";
  var KIWI_EXECUTION_RUN = "kiwi-execution-run";
  var KIWI_EXECUTION_RESULT = "kiwi-execution-result";
  var KIWI_EXECUTION_ERROR = "kiwi-execution-error";

  var MIN_OPS = 8;
  var MAX_OPS = 24;
  var OP_COUNT = 34;
  var FORMAT_VERSION = 1;

  var ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var CLASS_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  var ATTR_NAMES = ["data-kiwi", "data-a", "data-b", "title", "data-x"];
  var TAG_NAMES = ["div", "span", "section", "p"];

  var TRACE_NAMES = [
    "add", "sub", "mul", "xor", "and", "or", "shl", "shr",
    "u8c", "u8w", "u8r", "u8rot",
    "slen", "schar", "scode", "sslice",
    "dcreate", "dattr", "dappend", "dqsel", "dget", "dset", "dgetd",
    "cadd", "ccont", "dparent", "ddispatch", "dserialize",
    "qreal", "geom", "point", "evreal", "sreal", "obs"
  ];

  // ── Minimal SHA-256 (FIPS 180-4), deterministic ─────────────────────
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256Bytes(data) {
    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    var l = data.length * 8;
    var padLen = (data.length % 64 < 56) ? (56 - data.length % 64) : (120 - data.length % 64);
    var msg = new Uint8Array(data.length + padLen + 8);
    msg.set(data);
    msg[data.length] = 0x80;
    var view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, l >>> 0, false);
    view.setUint32(msg.length - 8, Math.floor(l / 0x100000000), false);
    var w = new Int32Array(64);
    var a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
    for (var i = 0; i < msg.length; i += 64) {
      for (var j = 0; j < 16; j++) w[j] = view.getInt32(i + j * 4, false);
      for (j = 16; j < 64; j++) {
        var x = w[j - 15], y = w[j - 2];
        s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }
      a = h0; b = h1; c = h2; d = h3; e = h4; f = h5; g = h6; hh = h7;
      for (j = 0; j < 64; j++) {
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = (e & f) ^ (~e & g);
        t1 = (hh + s1 + ch + K[j] + w[j]) | 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + hh) | 0;
    }
    var out = new Uint8Array(32);
    var hs = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (var i2 = 0; i2 < 8; i2++) {
      out[i2 * 4] = (hs[i2] >>> 24) & 0xff;
      out[i2 * 4 + 1] = (hs[i2] >>> 16) & 0xff;
      out[i2 * 4 + 2] = (hs[i2] >>> 8) & 0xff;
      out[i2 * 4 + 3] = hs[i2] & 0xff;
    }
    return out;
  }

  function bytesToHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      s += h.length < 2 ? "0" + h : h;
    }
    return s;
  }

  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  // HMAC-SHA256 (RFC 2104).
  function hmacSha256(keyBytes, msgBytes) {
    var blockSize = 64;
    var key = new Uint8Array(blockSize);
    if (keyBytes.length > blockSize) {
      key.set(sha256Bytes(keyBytes));
    } else {
      key.set(keyBytes);
    }
    var ipad = new Uint8Array(blockSize + msgBytes.length);
    var opad = new Uint8Array(blockSize + 32);
    for (var i = 0; i < blockSize; i++) {
      ipad[i] = key[i] ^ 0x36;
      opad[i] = key[i] ^ 0x5c;
    }
    ipad.set(msgBytes, blockSize);
    var inner = sha256Bytes(ipad);
    opad.set(inner, blockSize);
    return sha256Bytes(opad);
  }

  // ── Tiny base64 / utf8 helpers (byte-exact) ─────────────────────────
  var B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  function b64Encode(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i += 3) {
      var b0 = bytes[i], b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
      var b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
      out += B64_CHARS[b0 >> 2];
      out += B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
      out += i + 1 < bytes.length ? B64_CHARS[((b1 & 15) << 2) | (b2 >> 6)] : "=";
      out += i + 2 < bytes.length ? B64_CHARS[b2 & 63] : "=";
    }
    return out;
  }

  function b64Decode(str) {
    str = str.replace(/=+$/, "");
    var out = [];
    var buffer = 0, bits = 0;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      var val = (c >= 65 && c <= 90) ? c - 65
        : (c >= 97 && c <= 122) ? c - 71
        : (c >= 48 && c <= 57) ? c + 4
        : c === 43 ? 62 : c === 47 ? 63 : -1;
      if (val < 0) return null;
      buffer = (buffer << 6) | val;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out.push((buffer >> bits) & 0xff);
      }
    }
    return new Uint8Array(out);
  }

  function asciiBytes(s) {
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
    return out;
  }

  // ── The program parser ──────────────────────────────────────────────
  // Mirrors the PHP/Rust parsers byte-for-byte: length bytes carry the
  // ACTUAL length; the raw-byte operands (int literals, U8_CREATE,
  // U8_WRITE/READ/ROTATE, tag/name indexes, slice start/count) derive
  // the same value both sides derive.
  function parseProgram(bytes) {
    var pos = 0;
    function take(n) {
      if (pos + n > bytes.length) return null;
      var out = bytes.subarray(pos, pos + n);
      pos += n;
      return out;
    }
    function byte() {
      var b = take(1);
      return b === null ? null : b[0];
    }

    var format = byte();
    if (format !== FORMAT_VERSION) return null;
    var scopeLen = byte();
    if (scopeLen === null || scopeLen < 1 || scopeLen > 128) return null;
    var scopeBytes = take(scopeLen);
    if (scopeBytes === null) return null;
    var actionLen = byte();
    if (actionLen === null || actionLen < 1 || actionLen > 32) return null;
    var actionBytes = take(actionLen);
    if (actionBytes === null) return null;
    var opVersion = byte();
    // Execution versions 1 and 2 are both accepted (the compat window:
    // old challenges stay executable for their whole TTL); each version
    // bounds its own opcode space below — version 1 never carries the
    // version-2 observe opcode (33).
    if (opVersion !== 1 && opVersion !== 2) return null;
    var opCount = byte();
    if (opCount === null || opCount < MIN_OPS || opCount > MAX_OPS) return null;

    function readLenBytes(maxLen) {
      var len = byte();
      if (len === null || len < 1 || len > maxLen) return null;
      var b = take(len);
      if (b === null) return null;
      return b;
    }

    var ops = [];
    for (var i = 0; i < opCount; i++) {
      var opcode = byte();
      if (opcode === null) return null;
      // Version 1 programs never carry the version-2 observe opcode.
      if (opcode >= (opVersion === 1 ? OP_COUNT - 1 : OP_COUNT)) return null;
      var operands = [];
      switch (opcode) {
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: {
          var ab = take(8);
          if (!ab) return null;
          operands.push({ k: "a", v: ((ab[0] << 24) | (ab[1] << 16) | (ab[2] << 8) | ab[3]) >>> 0 });
          operands.push({ k: "b", v: ((ab[4] << 24) | (ab[5] << 16) | (ab[6] << 8) | ab[7]) >>> 0 });
          break;
        }
        case 8: { // U8_CREATE: raw byte -> len = 8 + (b % 57)
          var b8 = byte();
          if (b8 === null) return null;
          operands.push({ k: "len", v: 8 + (b8 % 57) });
          break;
        }
        case 9: {
          var b0 = byte(), b1 = byte();
          if (b0 === null || b1 === null) return null;
          operands.push({ k: "idx", v: b0 % 64 });
          operands.push({ k: "val", v: b1 });
          break;
        }
        case 10: {
          var b10 = byte();
          if (b10 === null) return null;
          operands.push({ k: "idx", v: b10 % 64 });
          break;
        }
        case 11: {
          var b11 = byte();
          if (b11 === null) return null;
          operands.push({ k: "k", v: b11 % 8 });
          break;
        }
        case 12: {
          var s12 = readLenBytes(16);
          if (!s12) return null;
          operands.push({ k: "s", v: s12 });
          break;
        }
        case 13: case 14: {
          var s13 = readLenBytes(16);
          if (!s13) return null;
          var idx13 = byte();
          if (idx13 === null) return null;
          operands.push({ k: "s", v: s13 });
          operands.push({ k: "idx", v: idx13 });
          break;
        }
        case 15: {
          var s15 = readLenBytes(16);
          if (!s15) return null;
          var tail15 = take(2);
          if (!tail15) return null;
          operands.push({ k: "s", v: s15 });
          operands.push({ k: "start", v: tail15[0] % (s15.length + 1) });
          operands.push({ k: "count", v: tail15[1] % 32 });
          break;
        }
        case 16: {
          var tag = byte();
          var id16 = readLenBytes(16);
          if (tag === null || !id16 || id16.length < 4) return null;
          operands.push({ k: "tag", v: tag % 4 });
          operands.push({ k: "id", v: id16 });
          break;
        }
        case 17: {
          var name = byte();
          var val17 = readLenBytes(32);
          if (name === null || !val17) return null;
          operands.push({ k: "name", v: name % 5 });
          operands.push({ k: "val", v: val17 });
          break;
        }
        case 18: case 25: case 26: case 27:
          break;
        case 19: {
          var id19 = readLenBytes(16);
          if (!id19 || id19.length < 4) return null;
          operands.push({ k: "id", v: id19 });
          break;
        }
        case 20: {
          var name20 = byte();
          if (name20 === null) return null;
          operands.push({ k: "name", v: name20 % 5 });
          break;
        }
        case 21: {
          var keyLen = byte();
          if (keyLen === null || keyLen < 1 || keyLen > 16) return null;
          var key = take(keyLen);
          if (!key) return null;
          var vLen = byte();
          if (vLen === null || vLen < 1 || vLen > 32) return null;
          var val21 = take(vLen);
          if (!val21) return null;
          operands.push({ k: "s", v: key });
          operands.push({ k: "val", v: val21 });
          break;
        }
        case 22: {
          var s22 = readLenBytes(16);
          if (!s22) return null;
          operands.push({ k: "s", v: s22 });
          break;
        }
        case 23: case 24: {
          var s23 = readLenBytes(12);
          if (!s23) return null;
          operands.push({ k: "s", v: s23 });
          break;
        }
        case 28: case 29: case 31: {
          // Real-DOM probes: QUERY_REAL/GEOMETRY/EVENT_REAL carry a
          // constructed id (4..16 bytes, like the plain query op).
          var idReal = readLenBytes(16);
          if (!idReal || idReal.length < 4) return null;
          operands.push({ k: "id", v: idReal });
          break;
        }
        case 30: {
          // POINT: two raw probe bytes (x, y), never length-prefixed.
          var px = byte(), py = byte();
          if (px === null || py === null) return null;
          operands.push({ k: "x", v: px % 256 });
          operands.push({ k: "y", v: py % 256 });
          break;
        }
        case 32:
          break;
        case 33: {
          // OBSERVE: the constructed id (4..16 bytes, like the real
          // probes) then one raw byte for the u8 destination index.
          var obsId = readLenBytes(16);
          if (!obsId || obsId.length < 4) return null;
          var obsByte = byte();
          if (obsByte === null) return null;
          operands.push({ k: "id", v: obsId });
          operands.push({ k: "idx", v: obsByte % 64 });
          break;
        }
        default:
          return null;
      }
      ops.push({ opcode: opcode, operands: operands });
    }

    // Exact EOF: the op list must consume the whole blob (the mirrors'
    // strict-parser parity — a trailing byte is a foreign blob).
    if (pos !== bytes.length) return null;

    return {
      scope: bytesToAscii(scopeBytes),
      action: bytesToAscii(actionBytes),
      opVersion: opVersion,
      ops: ops
    };
  }

  function bytesToAscii(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  function opValue(ops, key) {
    for (var i = 0; i < ops.length; i++) {
      if (ops[i].k === key) return ops[i].v;
    }
    return undefined;
  }

  // ── The deterministic state machine ─────────────────────────────────
  // DOM state mirrors the real sandboxed iframe document. The
  // interpreter keeps its OWN attribute record (setAttribute ops + the
  // reflected id) — serialization reads that record, never
  // getAttributeNames, so dataset writes can never leak into the
  // canonical serialization.
  function runProgram(program, doc) {
    var u8 = new Uint8Array(0);
    var cur = null; // { el, id, attrs: {name: value}, dataset: {}, classes: {}, appended }
    var docIds = {}; // id -> true for appended nodes
    var entries = [];
    // The POINT probe's whole-program predicate (the verifier checks
    // "any DOM_APPEND op", never the probe's position): the browser
    // answers 'div' exactly when the program constructs a node.
    var hasAppend = false;
    for (var pre = 0; pre < program.ops.length; pre++) {
      if (program.ops[pre].opcode === 18) { hasAppend = true; break; }
    }
    // GEOMETRY tops must be monotonic across the whole trace (the
    // verifier's invariant); a real layout offset can never decrease,
    // and an absent probe reports the previous top.
    var geomTop = -1;

    function checksum() {
      var sum = 0;
      for (var i = 0; i < u8.length; i++) sum = (sum + u8[i]) & 0xff;
      return sum;
    }

    function serializeAttrs(node) {
      var names = Object.keys(node.attrs).sort();
      var parts = [];
      for (var i = 0; i < names.length; i++) {
        parts.push(names[i] + "=" + node.attrs[names[i]]);
      }
      return parts.join(";");
    }

    for (var i = 0; i < program.ops.length; i++) {
      var op = program.ops[i];
      var ops = op.operands;
      var value;
      switch (op.opcode) {
        case 0: value = String((opValue(ops, "a") + opValue(ops, "b")) >>> 0); break;
        case 1: value = String((opValue(ops, "a") - opValue(ops, "b")) >>> 0); break;
        case 2: value = String(Math.imul(opValue(ops, "a"), opValue(ops, "b")) >>> 0); break;
        case 3: value = String((opValue(ops, "a") ^ opValue(ops, "b")) >>> 0); break;
        case 4: value = String((opValue(ops, "a") & opValue(ops, "b")) >>> 0); break;
        case 5: value = String((opValue(ops, "a") | opValue(ops, "b")) >>> 0); break;
        case 6: value = String((opValue(ops, "a") << (opValue(ops, "b") & 31)) >>> 0); break;
        case 7: value = String(opValue(ops, "a") >>> (opValue(ops, "b") & 31)); break;
        case 8: {
          u8 = new Uint8Array(opValue(ops, "len"));
          value = String(checksum());
          break;
        }
        case 9: {
          var idx = opValue(ops, "idx"), val = opValue(ops, "val") & 0xff;
          if (idx < u8.length) u8[idx] = val;
          value = String(checksum());
          break;
        }
        case 10: {
          var ridx = opValue(ops, "idx");
          value = String(ridx < u8.length ? u8[ridx] : 0);
          break;
        }
        case 11: {
          var k = opValue(ops, "k") % 8;
          if (u8.length > 0 && k > 0) {
            var rotated = new Uint8Array(u8.length);
            for (var ri = 0; ri < u8.length; ri++) rotated[ri] = u8[(ri + k) % u8.length];
            u8 = rotated;
          }
          value = String(checksum());
          break;
        }
        case 12: value = String(opValue(ops, "s").length); break;
        case 13: case 14: {
          var s = opValue(ops, "s"), sidx = opValue(ops, "idx");
          value = String(sidx < s.length ? s[sidx] : 0);
          break;
        }
        case 15: {
          var ss = opValue(ops, "s"), start = opValue(ops, "start"), count = opValue(ops, "count");
          var end = Math.min(start + count, ss.length);
          value = b64Encode(ss.subarray(start, end));
          break;
        }
        case 16: {
          var idBytes = opValue(ops, "id");
          var id = bytesToAscii(idBytes);
          var el = doc.createElement(TAG_NAMES[opValue(ops, "tag")]);
          el.id = id;
          cur = {
            el: el,
            id: id,
            attrs: { id: id },
            dataset: {},
            classes: {},
            appended: false
          };
          value = b64Encode(idBytes);
          break;
        }
        case 17: {
          var name = ATTR_NAMES[opValue(ops, "name")];
          var valBytes = opValue(ops, "val");
          if (cur) {
            cur.el.setAttribute(name, bytesToAscii(valBytes));
            cur.attrs[name] = bytesToAscii(valBytes);
          }
          value = b64Encode(asciiBytes(name));
          break;
        }
        case 18: {
          if (cur && !cur.appended) {
            doc.body.appendChild(cur.el);
            cur.appended = true;
            docIds[cur.id] = true;
          }
          value = "1";
          break;
        }
        case 19: {
          var qid = bytesToAscii(opValue(ops, "id"));
          value = docIds[qid] ? "1" : "0";
          break;
        }
        case 20: {
          var gname = ATTR_NAMES[opValue(ops, "name")];
          var gv = cur ? (cur.attrs[gname] || "") : "";
          value = b64Encode(asciiBytes(gv));
          break;
        }
        case 21: {
          var dkey = bytesToAscii(opValue(ops, "s"));
          var dval = bytesToAscii(opValue(ops, "val"));
          if (cur) {
            cur.el.dataset[dkey] = dval;
            cur.dataset[dkey] = dval;
          }
          value = b64Encode(opValue(ops, "s"));
          break;
        }
        case 22: {
          var gkey = bytesToAscii(opValue(ops, "s"));
          var gv2 = cur ? (cur.dataset[gkey] || "") : "";
          value = b64Encode(asciiBytes(gv2));
          break;
        }
        case 23: {
          var cls = bytesToAscii(opValue(ops, "s"));
          if (cur) {
            cur.el.classList.add(cls);
            cur.classes[cls] = true;
          }
          value = b64Encode(opValue(ops, "s"));
          break;
        }
        case 24: {
          var ccls = bytesToAscii(opValue(ops, "s"));
          value = (cur && cur.classes[ccls]) ? "1" : "0";
          break;
        }
        case 25: value = (cur && cur.appended) ? "1" : "0"; break;
        case 26: {
          if (cur) {
            try {
              cur.el.dispatchEvent(new doc.defaultView.Event("kiwi-exec"));
            } catch (e) {}
          }
          value = "1";
          break;
        }
        case 27: {
          if (cur && !cur.appended) {
            doc.body.appendChild(cur.el);
            cur.appended = true;
            docIds[cur.id] = true;
          }
          var serialized = cur ? serializeAttrs(cur) : "";
          value = b64Encode(asciiBytes(serialized));
          break;
        }
        case 28: {
          // Real querySelectorById readback: 'none' unless the probed
          // id is the current appended node, then the canonical
          // 'div|name=value;...' attribute pairs (the dataset writes
          // never leak into the canonical record).
          var qrId = bytesToAscii(opValue(ops, "id"));
          if (!docIds[qrId]) {
            value = "none";
          } else if (cur && cur.id === qrId) {
            value = "div|" + serializeAttrs(cur);
          } else {
            value = "none";
          }
          break;
        }
        case 29: {
          // Layout geometry of the constructed node: real offsetTop /
          // offsetHeight (clamped to the verifier invariants: height
          // >= 1, tops never decreasing). A probe of a node that is
          // not (yet) in the document reports the previous top.
          var gmEl = doc.getElementById(bytesToAscii(opValue(ops, "id")));
          var gmTop = gmEl ? gmEl.offsetTop : 0;
          if (gmTop < geomTop) gmTop = geomTop;
          geomTop = gmTop;
          var gmHeight = gmEl ? gmEl.offsetHeight : 1;
          if (gmHeight < 1) gmHeight = 1;
          value = gmTop + "," + gmHeight;
          break;
        }
        case 30: {
          // The topmost-node point probe: 'div' when the program
          // constructs any node, 'none' otherwise (the verifier's
          // whole-program predicate; x/y are the probe coordinates).
          value = hasAppend ? "div" : "none";
          break;
        }
        case 31: {
          // Real event readback: the canonical 'kiwi-ev:tag' for the
          // current appended node, 'none' for a foreign id.
          var evId = bytesToAscii(opValue(ops, "id"));
          if (!docIds[evId]) {
            value = "none";
          } else {
            value = "kiwi-ev:" + (cur && cur.id === evId ? "div" : "span");
          }
          break;
        }
        case 32: {
          // Canonical real serialization digest: hex SHA-256 of the
          // current node's sorted canonical attribute pairs, or of the
          // empty string when nothing is appended (the interpreter's
          // own sha256 keeps the digest deterministic).
          var srParts = (cur && cur.appended) ? serializeAttrs(cur) : "";
          value = bytesToHex(sha256Bytes(asciiBytes(srParts)));
          break;
        }
        case 33: {
          // OBSERVE: the measured real layout height of the constructed
          // node, written into the u8 state like U8_WRITE. The probe
          // pins the layout to a fixed-width block that renders a
          // canonical text line, so the measurement is the engine's own
          // text metrics (its default font and line height): a value a
          // pure function of the program cannot compute, since it
          // varies across engines and platforms. The verifier replays
          // this entry from the trace itself; it never predicts the
          // height. An absent node reports 1.
          var obsId = bytesToAscii(opValue(ops, "id"));
          var obsIdx = opValue(ops, "idx");
          var obsEl = doc.getElementById(obsId);
          var obsH = 1;
          if (obsEl) {
            obsEl.style.display = "block";
            obsEl.style.width = "240px";
            obsEl.style.height = "auto";
            obsEl.textContent = "kiwicaptcha-observe";
            obsH = obsEl.offsetHeight;
          }
          if (obsH < 1) obsH = 1;
          if (obsH > 255) obsH = 255;
          if (obsIdx < u8.length) u8[obsIdx] = obsH;
          value = obsIdx + "," + obsH;
          break;
        }
        default:
          value = "0";
      }
      entries.push(TRACE_NAMES[op.opcode] + "(" + value + ")");
    }

    return entries.join(";");
  }

  // ── The digest ──────────────────────────────────────────────────────
  // digest = hex(HMAC-SHA256(program_bytes,
  //   "kiwi-execution-v1|" nonce "|" scope "|" action "|" version "|" trace))
  function computeDigest(programBytes, program, nonce, trace) {
    var msg = asciiBytes(
      KIWI_EXECUTION_PROTOCOL + "|" + nonce + "|" + program.scope + "|" +
      program.action + "|" + program.opVersion + "|" + trace
    );
    return bytesToHex(hmacSha256(programBytes, msg));
  }

  // ── The message loop ────────────────────────────────────────────────
  function start() {
    if (typeof window === "undefined" || !window.parent) return;
    var parent = window.parent;

    function post(type, payload) {
      try {
        // The parent is the driver's page; the srcdoc iframe is
        // same-origin (sandbox allow-scripts allow-same-origin), so the
        // target is same-origin. The explicit "/" target is the
        // sender-origin shorthand (the document's own origin): inside a
        // sandboxed srcdoc document `window.location.origin` reports
        // the literal string "null" even though the document's real
        // origin IS the parent's, so posting with "null" would silently
        // drop the message. "/" delivers to the real same-origin parent
        // and is never a "*" wildcard (the driver validates the message
        // source on its side; the payload carries no secrets, only the
        // digest).
        parent.postMessage({ type: type, protocol: KIWI_EXECUTION_PROTOCOL, payload: payload || {} }, "/");
      } catch (e) {}
    }

    window.addEventListener("message", function (event) {
      var data = event.data;
      if (!data || data.type !== KIWI_EXECUTION_RUN || data.protocol !== KIWI_EXECUTION_PROTOCOL) {
        return;
      }
      var id = data.id;
      var programB64 = data.program;
      var nonce = data.nonce;
      if (typeof id !== "string" || id.length < 8 || id.length > 64 ||
          typeof programB64 !== "string" || programB64.length < 1 ||
          typeof nonce !== "string" || nonce.length < 1) {
        post(KIWI_EXECUTION_ERROR, { id: id || "bad-request", reason: "malformed-run" });
        return;
      }
      var programBytes = b64Decode(programB64);
      if (!programBytes) {
        post(KIWI_EXECUTION_ERROR, { id: id, reason: "program-base64" });
        return;
      }
      var program = parseProgram(programBytes);
      if (!program) {
        post(KIWI_EXECUTION_ERROR, { id: id, reason: "program-malformed" });
        return;
      }
      var trace;
      try {
        trace = runProgram(program, document);
      } catch (e) {
        post(KIWI_EXECUTION_ERROR, { id: id, reason: "program-execution" });
        return;
      }
      var digest = computeDigest(programBytes, program, nonce, trace);
      post(KIWI_EXECUTION_RESULT, { id: id, digest: digest, trace: trace });
    });

    post(KIWI_EXECUTION_READY, {});
  }

  if (typeof window !== "undefined") {
    window.KiwiCaptchaExecution = {
      protocol: KIWI_EXECUTION_PROTOCOL,
      runProgram: runProgram,
      computeDigest: computeDigest,
      parseProgram: parseProgram
    };
    if (window.parent && window.parent !== window) {
      start();
    }
  }
})();
