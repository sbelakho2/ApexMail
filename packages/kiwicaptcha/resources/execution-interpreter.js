/*!
* KiwiCaptcha execution interpreter — ExecutionChallengeV1. FIXED,
* AUDITED asset, lazy-loaded by the driver (execution.<sha256>.js) only
* when a challenge response carries an execution program; a SHA-only
* page never fetches this file.
*
* Deterministic bytecode VM: no dynamic code construction, no
* Math.random, no Date in the op semantics — a program is a pure
* function of its bytes, so the server mirrors recompute the identical
* canonical op trace and digest. Opcode split: COMPUTE 0-15, DOM 16-27,
* real-DOM probes 28-36, v5 object-graph ops 37-44, v6 real-platform
* probes 45-49. The op-count bound (8..24 ops) keeps a whole run ~0.1 ms
* on a low-end device (a v6 run adds two animation frames for the
* intersection probe).
*
* Version 6 is the real-platform rung: its five probes read behavior a
* pure reimplementation cannot shortcut (computed style over real
* layout, MutationObserver microtask delivery order, the full
* capture/target/bubble event path, Range line boxes and Selection
* state, IntersectionObserver thresholds over real geometry). Each v6
* probe runs on freshly constructed anonymous nodes it removes before
* returning, so the program-visible DOM state is unchanged. The probe
* values are quantized observations; the server verifier derives an
* acceptance envelope per probe from the program operands, calibrated
* by the cross-engine qualification matrix.
*
* The driver runs it in a SANDBOXED EPHEMERAL IFRAME per armed
* challenge (srcdoc, sandbox="allow-scripts allow-same-origin";
* allow-same-origin is required because an opaque-origin document
* cannot load a same-origin script under the recommended CSP; forms,
* popups, top-navigation and pointer lock stay blocked). The iframe
* loads this asset via <script src integrity=...> (CSP-clean,
* SRI-pinned) and the driver accepts messages only from that iframe.
* A version-6 run awaits microtasks and animation frames before the
* result message posts, so the run message resolves a few frames later
* than the synchronous rungs (the parent-side timeout is far above it).
*
* Trace format: one `opname(result)` entry per op joined with ';';
* results are decimal integers, "1"/"0", or standard base64; the
* browser-observed entries 'obs(<dst>,<h>)' and (v5) 'durlc(<64 hex>)'
* are replayed by the verifier; the v6 entries are comma/colon-joined
* digit tuples validated against their envelope. Digest: hex HMAC-SHA256
* keyed by the PROGRAM BYTES (the execution_key never leaves the
* server) over
* `kiwi-execution-v1|nonce|scope|action|version|canonical_op_trace`.
* The VM runs its own SHA-256 + HMAC-SHA256 (crypto.subtle may be
* unavailable there; synchronous code keeps the digest deterministic).
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
 var OP_COUNT = 50;
 // OP_SPACE[opVersion] = the first opcode each program version rejects.
 var OP_SPACE = [0, 33, 34, 35, 37, 45, OP_COUNT];
 var FORMAT_VERSION = 1;
 var ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 var CLASS_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
 var ATTR_NAMES = ["data-kiwi", "data-a", "data-b", "title", "data-x"];
 var TAG_NAMES = ["div", "span", "section", "p"];
 // The version-6 probe vocabularies. The server mirrors carry the same
 // constants and derive the acceptance envelope from the same draw
 // bytes, so a probe word or span word is randomized per program yet
 // bounded identically on both sides.
 var CSS_WORDS = ["kiwicaptcha", "execution", "boundary"];
 var RANGE_WORDS = ["alpha", "beta", "gamma", "delta"];
 var TRACE_NAMES = [
  "add", "sub", "mul", "xor", "and", "or", "shl", "shr",
  "u8c", "u8w", "u8r", "u8rot",
  "slen", "schar", "scode", "sslice",
  "dcreate", "dattr", "dappend", "dqsel", "dget", "dset", "dgetd",
  "cadd", "ccont", "dparent", "ddispatch", "dserialize",
  "qreal", "geom", "point", "evreal", "sreal", "obs", "dsib", "dchild", "ddepth",
  "dfrag", "dclone", "drepar", "dreflec", "dphase", "durlc", "dmutate", "dsdep",
  "dcsgeom", "dmutord", "devphf", "drange", "dintobs"
 ];
 // ── SHA-256 (FIPS 180-4) ──
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
 // ── Base64 / utf8 helpers ──
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
 // ── The program parser ──
 // Mirrors the PHP/Rust parsers byte-for-byte.
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
  // Versions 1..6 accepted (the compat window); each bounds its opcode space (OP_SPACE).
  if (opVersion < 1 || opVersion > 6) return null;
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
   var maxOpcode = OP_SPACE[opVersion];
   if (opcode >= maxOpcode) return null;
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
    case 16: case 35: {
     // DCREATE/DCHILD share the tag-byte + id shape.
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
    case 19: case 28: case 29: case 31: case 34: case 36: {
     // Query/probe/DSIB/DDEPTH: one constructed id (4..16 bytes).
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
     // OBSERVE: the constructed id then one raw byte for the u8 index.
     var obsId = readLenBytes(16);
     if (!obsId || obsId.length < 4) return null;
     var obsByte = byte();
     if (obsByte === null) return null;
     operands.push({ k: "id", v: obsId });
     operands.push({ k: "idx", v: obsByte % 64 });
     break;
    }
    case 37: {
     // DFRAG: the fragment slot byte (s % 4) then a raw cell byte.
     var fgA = byte(), fgB = byte();
     if (fgA === null || fgB === null) return null;
     operands.push({ k: "s", v: fgA % 4 });
     operands.push({ k: "cell", v: fgB % 64 });
     break;
    }
    case 38: case 39: {
     // DCLONE/DREPAR: the target id then a raw cell byte.
     var clId = readLenBytes(16);
     if (!clId || clId.length < 4) return null;
     var clCell = byte();
     if (clCell === null) return null;
     operands.push({ k: "id", v: clId });
     operands.push({ k: "cell", v: clCell % 64 });
     break;
    }
    case 40: {
     var rfByte = byte();
     if (rfByte === null) return null;
     operands.push({ k: "name", v: rfByte % 5 });
     break;
    }
    case 41: {
     var phByte = byte();
     if (phByte === null) return null;
     operands.push({ k: "cell", v: phByte % 64 });
     break;
    }
    case 42:
     break;
    case 43: {
     // DMUTATE: a printable value then a raw cell byte.
     var dmVal = readLenBytes(32);
     if (!dmVal) return null;
     var dmCell = byte();
     if (dmCell === null) return null;
     operands.push({ k: "val", v: dmVal });
     operands.push({ k: "cell", v: dmCell % 64 });
     break;
    }
    case 44: {
     var dsA = byte(), dsB = byte(), dsC = byte();
     if (dsA === null || dsB === null || dsC === null) return null;
     operands.push({ k: "b0", v: dsA });
     operands.push({ k: "b1", v: dsB });
     operands.push({ k: "b2", v: dsC });
     break;
    }
    case 45: {
     // CSS_GEOM: the constructed id, the raw style seed and the u8 cell.
     var cgId = readLenBytes(16);
     if (!cgId || cgId.length < 4) return null;
     var cgSeed = byte(), cgCell = byte();
     if (cgSeed === null || cgCell === null) return null;
     operands.push({ k: "id", v: cgId });
     operands.push({ k: "seed", v: cgSeed });
     operands.push({ k: "cell", v: cgCell % 64 });
     break;
    }
    case 46: {
     // MUT_ORDER: the constructed id, two raw churn bytes and the cell.
     var moId = readLenBytes(16);
     if (!moId || moId.length < 4) return null;
     var moB0 = byte(), moB1 = byte(), moCell = byte();
     if (moB0 === null || moB1 === null || moCell === null) return null;
     operands.push({ k: "id", v: moId });
     operands.push({ k: "b0", v: moB0 });
     operands.push({ k: "b1", v: moB1 });
     operands.push({ k: "cell", v: moCell % 64 });
     break;
    }
    case 47: {
     // EV_PHASE_FULL: the constructed id and the u8 cell.
     var evId = readLenBytes(16);
     if (!evId || evId.length < 4) return null;
     var evCell = byte();
     if (evCell === null) return null;
     operands.push({ k: "id", v: evId });
     operands.push({ k: "cell", v: evCell % 64 });
     break;
    }
    case 48: {
     // RANGE_ORDER: the constructed id, two raw offset bytes and the cell.
     var rgId = readLenBytes(16);
     if (!rgId || rgId.length < 4) return null;
     var rgA = byte(), rgB = byte(), rgCell = byte();
     if (rgA === null || rgB === null || rgCell === null) return null;
     operands.push({ k: "id", v: rgId });
     operands.push({ k: "ra", v: rgA });
     operands.push({ k: "rb", v: rgB });
     operands.push({ k: "cell", v: rgCell % 64 });
     break;
    }
    case 49: {
     // INT_OBS: the constructed id, the raw geometry seed and the cell.
     var ioId = readLenBytes(16);
     if (!ioId || ioId.length < 4) return null;
     var ioSeed = byte(), ioCell = byte();
     if (ioSeed === null || ioCell === null) return null;
     operands.push({ k: "id", v: ioId });
     operands.push({ k: "seed", v: ioSeed });
     operands.push({ k: "cell", v: ioCell % 64 });
     break;
    }
    default:
     return null;
   }
   ops.push({ opcode: opcode, operands: operands });
  }
  // Exact EOF: a trailing byte is a foreign blob (strict-parser parity).
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
 function opId(ops) {
  return bytesToAscii(opValue(ops, "id"));
 }
 // ── The deterministic state machine ──
 // Serialization reads this module's own attribute record, never getAttributeNames.
 // The state lives in one runner object shared by the synchronous rungs
 // (versions 1-5) and the asynchronous version-6 run, so both paths
 // execute the identical op semantics.
 function createRunner(doc, v5) {
  var R = {
   doc: doc,
   v5: v5,
   u8: new Uint8Array(0),
   cur: null, // { el, id, attrs: {name: value}, dataset: {}, classes: {}, appended }
   docIds: Object.create(null), // id -> true for appended nodes (null-proto: id is program-controlled)
   entries: [],
   frags: [null, null, null, null], // the four v5 fragment slots
   hasAppend: false,
   geomTop: -1
  };
  R.checksum = function () {
   var sum = 0;
   for (var i = 0; i < R.u8.length; i++) sum = (sum + R.u8[i]) & 0xff;
   return sum;
  };
  R.serializeAttrs = function (node) {
   var names = Object.keys(node.attrs).sort();
   var parts = [];
   for (var i = 0; i < names.length; i++) {
    parts.push(names[i] + "=" + node.attrs[names[i]]);
   }
   return parts.join(";");
  };
  // The v5 cell rule: the entry lands in the u8 cell when in range.
  R.writeCell = function (cell, entry) {
   if (cell < R.u8.length) R.u8[cell] = entry & 0xff;
  };
  R.appendCurrent = function () {
   if (R.cur && !R.cur.appended) {
    R.doc.body.appendChild(R.cur.el);
    R.cur.appended = true;
    R.docIds[R.cur.id] = true;
   }
  };
  R.copyMap = function (src) {
   var out = Object.create(null);
   for (var key in src) {
    if (Object.prototype.hasOwnProperty.call(src, key)) out[key] = src[key];
   }
   return out;
  };
  // URL canonicalization: scheme/host lowercased, fragment dropped (srcdoc-deterministic).
  R.canonicalUrl = function (href) {
   var h = String(href);
   var cut = h.indexOf("#");
   if (cut >= 0) h = h.substr(0, cut);
   var colon = h.indexOf(":");
   if (colon > 0) {
    var scheme = h.substr(0, colon).toLowerCase();
    var rest = h.substr(colon + 1);
    if (rest.substr(0, 2) === "//") {
     var end = rest.length;
     for (var i = 2; i < rest.length; i++) {
      var c = rest.charAt(i);
      if (c === "/" || c === "?") { end = i; break; }
     }
     rest = rest.substr(0, end).toLowerCase() + rest.substr(end);
    }
    h = scheme + ":" + rest;
   }
   return h;
  };
  // Rung-scoped canonical node string: serializeAttrs plus the v5 dataset/classes/text.
  R.canonicalNodeString = function (node) {
   if (!R.v5) return R.serializeAttrs(node);
   var s5 = R.serializeAttrs(node);
   var parts = s5 === "" ? [] : s5.split(";");
   var dnames = Object.keys(node.dataset || {}).sort();
   for (var j = 0; j < dnames.length; j++) parts.push(dnames[j] + "=" + node.dataset[dnames[j]]);
   var cnames = Object.keys(node.classes || {}).sort();
   for (var k = 0; k < cnames.length; k++) parts.push(cnames[k]);
   if (node.text !== undefined && node.text !== "") parts.push(node.text);
   return parts.join(";");
  };
  R.execOp = function (op) {
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
     R.u8 = new Uint8Array(opValue(ops, "len"));
     value = String(R.checksum());
     break;
    }
    case 9: {
     var idx = opValue(ops, "idx"), val = opValue(ops, "val") & 0xff;
     if (idx < R.u8.length) R.u8[idx] = val;
     value = String(R.checksum());
     break;
    }
    case 10: {
     var ridx = opValue(ops, "idx");
     value = String(ridx < R.u8.length ? R.u8[ridx] : 0);
     break;
    }
    case 11: {
     var k = opValue(ops, "k") % 8;
     if (R.u8.length > 0 && k > 0) {
      var rotated = new Uint8Array(R.u8.length);
      for (var ri = 0; ri < R.u8.length; ri++) rotated[ri] = R.u8[(ri + k) % R.u8.length];
      R.u8 = rotated;
     }
     value = String(R.checksum());
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
     var el = R.doc.createElement(TAG_NAMES[opValue(ops, "tag")]);
     el.id = id;
     R.cur = {
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
     if (R.cur) {
      R.cur.el.setAttribute(name, bytesToAscii(valBytes));
      R.cur.attrs[name] = bytesToAscii(valBytes);
     }
     value = b64Encode(asciiBytes(name));
     break;
    }
    case 18: {
     R.appendCurrent();
     value = "1";
     break;
    }
    case 19: {
     var qid = bytesToAscii(opValue(ops, "id"));
     value = R.docIds[qid] ? "1" : "0";
     break;
    }
    case 20: {
     var gname = ATTR_NAMES[opValue(ops, "name")];
     var gv = R.cur ? (R.cur.attrs[gname] || "") : "";
     value = b64Encode(asciiBytes(gv));
     break;
    }
    case 21: {
     var dkey = bytesToAscii(opValue(ops, "s"));
     var dval = bytesToAscii(opValue(ops, "val"));
     if (R.cur) {
      R.cur.el.dataset[dkey] = dval;
      R.cur.dataset[dkey] = dval;
     }
     value = b64Encode(opValue(ops, "s"));
     break;
    }
    case 22: {
     var gkey = bytesToAscii(opValue(ops, "s"));
     var gv2 = R.cur ? (R.cur.dataset[gkey] || "") : "";
     value = b64Encode(asciiBytes(gv2));
     break;
    }
    case 23: {
     var cls = bytesToAscii(opValue(ops, "s"));
     if (R.cur) {
      R.cur.el.classList.add(cls);
      R.cur.classes[cls] = true;
     }
     value = b64Encode(opValue(ops, "s"));
     break;
    }
    case 24: {
     var ccls = bytesToAscii(opValue(ops, "s"));
     value = (R.cur && R.cur.classes[ccls]) ? "1" : "0";
     break;
    }
    case 25: value = (R.cur && R.cur.appended) ? "1" : "0"; break;
    case 26: {
     if (R.cur) {
      try {
       R.cur.el.dispatchEvent(new R.doc.defaultView.Event("kiwi-exec"));
      } catch (e) {}
     }
     value = "1";
     break;
    }
    case 27: {
     R.appendCurrent();
     var serialized = R.cur ? R.canonicalNodeString(R.cur) : "";
     value = b64Encode(asciiBytes(serialized));
     break;
    }
    case 28: {
     // Real query readback of the current appended node: 'div|...' or 'none'.
     var qrId = bytesToAscii(opValue(ops, "id"));
     if (!R.docIds[qrId]) {
      value = "none";
     } else if (R.cur && R.cur.id === qrId) {
      value = "div|" + R.serializeAttrs(R.cur);
     } else {
      value = "none";
     }
     break;
    }
    case 29: {
     // Real layout geometry, clamped to the verifier's invariants.
     var gmEl = R.doc.getElementById(bytesToAscii(opValue(ops, "id")));
     var gmTop = gmEl ? gmEl.offsetTop : 0;
     if (gmTop < R.geomTop) gmTop = R.geomTop;
     R.geomTop = gmTop;
     var gmHeight = gmEl ? gmEl.offsetHeight : 1;
     if (gmHeight < 1) gmHeight = 1;
     value = gmTop + "," + gmHeight;
     break;
    }
    case 30: {
     // The topmost-node point probe: 'div'/'none'.
     value = R.hasAppend ? "div" : "none";
     break;
    }
    case 31: {
     // Real event readback: 'kiwi-ev:tag' for the current node.
     var evId = bytesToAscii(opValue(ops, "id"));
     if (!R.docIds[evId]) {
      value = "none";
     } else {
      value = "kiwi-ev:" + (R.cur && R.cur.id === evId ? "div" : "span");
     }
     break;
    }
    case 32: {
     // Canonical digest: hex SHA-256 of the rung-scoped node string ("" if none appended).
     var srParts = (R.cur && R.cur.appended) ? R.canonicalNodeString(R.cur) : "";
     value = bytesToHex(sha256Bytes(asciiBytes(srParts)));
     break;
    }
    case 33: {
     // OBSERVE: real layout height into the u8 state; verifier-replayed. Absent: 1.
     var obsId = bytesToAscii(opValue(ops, "id"));
     var obsIdx = opValue(ops, "idx");
     var obsEl = R.doc.getElementById(obsId);
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
     if (obsIdx < R.u8.length) R.u8[obsIdx] = obsH;
     value = obsIdx + "," + obsH;
     break;
    }
    case 34: {
     // DSIB: real previousElementSibling chain length (absent node: 0).
     var dsibEl = R.doc.getElementById(bytesToAscii(opValue(ops, "id")));
     var dsibIdx = 0;
     while (dsibEl) {
       dsibEl = dsibEl.previousElementSibling;
       if (dsibEl) dsibIdx++;
     }
     value = "" + dsibIdx;
     break;
    }
    case 35: {
     // DCHILD: real child of the current node; it becomes current.
     var chId = bytesToAscii(opValue(ops, "id"));
     var chEl = R.doc.createElement(TAG_NAMES[opValue(ops, "tag")]);
     chEl.id = chId;
     if (R.cur && R.cur.el) R.cur.el.appendChild(chEl);
     R.cur = { el: chEl, id: chId, attrs: { id: chId }, dataset: {}, classes: {}, appended: true };
     value = b64Encode(asciiBytes(chId));
     break;
    }
    case 36: {
     // DDEPTH: real ancestor-chain length up to body.
     var ddEl = R.doc.getElementById(bytesToAscii(opValue(ops, "id")));
     var ddDepth = 0;
     while (ddEl && ddEl.parentElement && ddEl.parentElement !== R.doc.body) {
       ddDepth++;
       ddEl = ddEl.parentElement;
     }
     value = "" + ddDepth;
     break;
    }
    case 37: {
     // DFRAG: move the current subtree into the detached fragment slot.
     var fgEntry = 0;
     if (R.cur && R.cur.el) {
      var fgS = opValue(ops, "s");
      if (!R.frags[fgS]) R.frags[fgS] = R.doc.createDocumentFragment();
      R.frags[fgS].appendChild(R.cur.el);
      R.cur.appended = false;
      if (R.docIds[R.cur.id]) delete R.docIds[R.cur.id];
      fgEntry = R.frags[fgS].children.length;
     }
     R.writeCell(opValue(ops, "cell"), fgEntry);
     value = String(fgEntry);
     break;
    }
    case 38: {
     // DCLONE: real deep clone, re-id, insert after the original.
     var clId = bytesToAscii(opValue(ops, "id"));
     var clEntry = 0;
     if (R.cur && R.cur.el) {
      clEntry = R.cur.el.getElementsByTagName("*").length + 1;
      var copyEl = R.cur.el.cloneNode(true);
      copyEl.id = clId;
      if (R.cur.appended && R.cur.el.parentNode) R.cur.el.parentNode.insertBefore(copyEl, R.cur.el.nextSibling);
      var rec = { el: copyEl, id: clId, attrs: R.copyMap(R.cur.attrs), dataset: R.copyMap(R.cur.dataset), classes: R.copyMap(R.cur.classes), appended: R.cur.appended };
      rec.attrs.id = clId;
      if (R.cur.text !== undefined) rec.text = R.cur.text;
      if (R.cur.appended) R.docIds[clId] = true;
      R.cur = rec;
     }
     R.writeCell(opValue(ops, "cell"), clEntry);
     value = String(clEntry);
     break;
    }
    case 39: {
     // DREPAR: real appendChild of the current subtree under the target; self-move = real no-op.
     var rpEntry = 0;
     if (R.cur && R.cur.el) {
      var rpEl = R.doc.getElementById(bytesToAscii(opValue(ops, "id")));
      if (rpEl) {
       try {
        rpEl.appendChild(R.cur.el);
        R.cur.appended = !!rpEl.isConnected;
        if (R.cur.appended) R.docIds[R.cur.id] = true;
        else { if (R.docIds[R.cur.id]) delete R.docIds[R.cur.id]; }
       } catch (e) {}
       rpEntry = rpEl.children.length;
      }
     }
     R.writeCell(opValue(ops, "cell"), rpEntry);
     value = String(rpEntry);
     break;
    }
    case 40: {
     // DREFLEC: the indexed reflected attribute value.
     var rfName = ATTR_NAMES[opValue(ops, "name")];
     var rfVal = R.cur ? (R.cur.attrs[rfName] || "") : "";
     value = b64Encode(asciiBytes(rfVal));
     break;
    }
    case 41: {
     // DPHASE: real bubbling dispatch count of constructed elements.
     var phCount = 0;
     if (R.cur && R.cur.el) {
      var phH = function () { phCount++; };
      var phEl = R.cur.el;
      while (phEl && phEl !== R.doc.body) {
       phEl.addEventListener("kiwi-exec-phase", phH, false);
       phEl = phEl.parentElement;
      }
      try {
       R.cur.el.dispatchEvent(new R.doc.defaultView.Event("kiwi-exec-phase", { bubbles: true }));
      } catch (e) {}
      phEl = R.cur.el;
      while (phEl && phEl !== R.doc.body) {
       phEl.removeEventListener("kiwi-exec-phase", phH, false);
       phEl = phEl.parentElement;
      }
     }
     R.writeCell(opValue(ops, "cell"), phCount);
     value = String(phCount);
     break;
    }
    case 42: {
     // DURLC: SHA-256 hex of the canonicalized document URL.
     value = bytesToHex(sha256Bytes(asciiBytes(R.canonicalUrl(R.doc.defaultView && R.doc.defaultView.location ? R.doc.defaultView.location.href : R.doc.URL))));
     break;
    }
    case 43: {
     // DMUTATE: real textContent replacement; entry = text byte length.
     var dmVal = bytesToAscii(opValue(ops, "val"));
     var dmLen = 0;
     if (R.cur && R.cur.el) {
      var dmGone = [];
      for (var dmi = 0; dmi < R.cur.el.children.length; dmi++) dmGone.push(R.cur.el.children[dmi].id);
      R.cur.el.textContent = dmVal;
      R.cur.text = dmVal;
      dmLen = dmVal.length;
      for (var dmj = 0; dmj < dmGone.length; dmj++) {
       if (R.docIds[dmGone[dmj]]) delete R.docIds[dmGone[dmj]];
      }
     }
     R.writeCell(opValue(ops, "cell"), dmLen);
     value = String(dmLen);
     break;
    }
    case 44: {
     // DSDEP: descend real child elements by the three index bytes.
     var sdLevel = (R.cur && R.cur.el) ? R.cur.el : null;
     var sdDone = 0;
     var sdBytes = [opValue(ops, "b0"), opValue(ops, "b1"), opValue(ops, "b2")];
     while (sdLevel && sdDone < 3) {
      var sdKids = sdLevel.children;
      if (!sdKids.length) break;
      sdLevel = sdKids[sdBytes[sdDone] % sdKids.length];
      sdDone++;
     }
     value = String(sdDone);
     break;
    }
    default:
     value = "0";
   }
   return value;
  };
  return R;
 }
 function runProgram(program, doc) {
  var R = createRunner(doc, program.opVersion >= 5);
  var pre;
  for (pre = 0; pre < program.ops.length; pre++) {
   if (program.ops[pre].opcode === 18) { R.hasAppend = true; break; }
  }
  if (program.opVersion <= 5) {
   for (var i = 0; i < program.ops.length; i++) {
    var op = program.ops[i];
    R.entries.push(TRACE_NAMES[op.opcode] + "(" + R.execOp(op) + ")");
   }
   return R.entries.join(";");
  }
  return runProgramV6(R, program.ops);
 }
 // The version-6 run: identical op semantics with the five real-platform
 // probes (45-49) awaited in sequence. The promise resolves with the same
 // canonical trace string the synchronous rungs return.
 function runProgramV6(R, ops) {
  return new Promise(function (resolve) {
   var i = 0;
   function step() {
    while (i < ops.length) {
     var op = ops[i++];
     if (op.opcode >= 45) {
      execPlatformOp(R, op).then(function (value) {
       R.entries.push(TRACE_NAMES[op.opcode] + "(" + value + ")");
       step();
      }, function () {
       // A platform probe that cannot run (a missing observer in a
       // non-browser host) reports 0; the envelope rejects the entry.
       R.entries.push(TRACE_NAMES[op.opcode] + "(0)");
       step();
      });
      return;
     }
     R.entries.push(TRACE_NAMES[op.opcode] + "(" + R.execOp(op) + ")");
    }
    resolve(R.entries.join(";"));
   }
   step();
  });
 }
 // The version-6 real-platform probes. Each requires the operand id to
 // reference a node the program constructed and appended (the real
 // construction proof), runs on freshly built anonymous nodes it removes
 // before returning (the program-visible document state is unchanged),
 // quantizes its observations and writes its primary observation into
 // the operand's u8 cell (the verifier replays the cell like the v5
 // observe rule).
 function execPlatformOp(R, op) {
  var ops = op.operands;
  switch (op.opcode) {
   case 45: return Promise.resolve(execCssGeom(R, ops));
   case 46: return execMutOrder(R, ops);
   case 47: return Promise.resolve(execEvPhaseFull(R, ops));
   case 48: return Promise.resolve(execRangeOrder(R, ops));
   case 49: return execIntObs(R, ops);
   default: return Promise.resolve("0");
  }
 }
 function execCssGeom(R, ops) {
  // Randomized-CSS computed geometry: a fresh probe element carries the
  // seed-drawn inline style (font size, border width, a probe word); the
  // entry reports the computed font size and the laid-out height of the
  // wrapped text, values only a real layout engine produces.
  var id = bytesToAscii(opValue(ops, "id"));
  if (!R.docIds[id]) return "none";
  var el = R.doc.getElementById(id);
  if (!el) return "none";
  var seed = opValue(ops, "seed");
  var fs = 10 + ((seed >> 5) % 5);
  var brd = 1 + ((seed >> 3) % 3);
  // Two words (a break opportunity between them) at the 64px probe
  // width: the measured height is the wrapped line-box stack, a real
  // layout quantity.
  var word = CSS_WORDS[seed % CSS_WORDS.length] + " " + CSS_WORDS[(seed + 1) % CSS_WORDS.length];
  var probe = R.doc.createElement("div");
  probe.style.cssText = "box-sizing:content-box;width:64px;" +
   "border-top-width:" + brd + "px;border-top-style:solid;" +
   "border-bottom-width:" + brd + "px;border-bottom-style:solid;" +
   "font-size:" + fs + "px;font-family:monospace;line-height:normal;";
  probe.textContent = word;
  el.appendChild(probe);
  var fsv = 0;
  try {
   var cs = R.doc.defaultView.getComputedStyle(probe);
   fsv = Math.round(parseFloat(cs.fontSize));
  } catch (e0) { fsv = 0; }
  if (!isFinite(fsv) || fsv < 0) fsv = 0;
  var h = probe.offsetHeight;
  if (!isFinite(h) || h < 0) h = 0;
  if (h > 255) h = 255;
  el.removeChild(probe);
  R.writeCell(opValue(ops, "cell"), h);
  return fsv + "," + h;
 }
 function execMutOrder(R, ops) {
  // MutationObserver delivery order: the observer is registered, the
  // seed-drawn churn (attributes, childList, characterData) runs, and a
  // promise marker is queued after it. The entry reports the record-type
  // codes in delivery order followed by the marker digit 7, the order
  // only a microtask-correct engine produces.
  return new Promise(function (resolve) {
   var id = bytesToAscii(opValue(ops, "id"));
   if (!R.docIds[id]) { resolve("none"); return; }
   var el = R.doc.getElementById(id);
   if (!el) { resolve("none"); return; }
   var b0 = opValue(ops, "b0"), b1 = opValue(ops, "b1");
   var codes = [];
   var mo;
   try {
    mo = new R.doc.defaultView.MutationObserver(function (recs) {
     for (var i = 0; i < recs.length; i++) {
      codes.push(recs[i].type === "attributes" ? 1 : recs[i].type === "childList" ? 2 : 3);
     }
    });
    mo.observe(el, { attributes: true, childList: true, characterData: true, subtree: true });
   } catch (e0) { resolve("0"); return; }
   // The churn is fully self-cleaning: the probe records the target's
   // prior attribute state and removes only the nodes it added, so the
   // program-visible document (the constructed tree under the target
   // included) is unchanged when the probe returns.
   var attrName = ATTR_NAMES[b0 % 5];
   var hadAttr = el.hasAttribute(attrName);
   var oldAttr = hadAttr ? el.getAttribute(attrName) : null;
   el.setAttribute(attrName, "m");
   var added = [];
   var kids = 1 + (b0 % 2);
   for (var k = 0; k < kids; k++) {
    var churnChild = R.doc.createElement(TAG_NAMES[(b1 + k) % 4]);
    el.appendChild(churnChild);
    added.push(churnChild);
   }
   var txt = R.doc.createTextNode("x");
   el.appendChild(txt);
   added.push(txt);
   if ((b1 & 1) === 1) txt.data = "y";
   Promise.resolve().then(function () { codes.push(7); });
   // One microtask yield: the observer microtask (queued at the first
   // mutation) and the marker continuation run before this one.
   Promise.resolve().then(function () {
    mo.disconnect();
    for (var r = 0; r < added.length; r++) {
     if (added[r].parentNode === el) el.removeChild(added[r]);
    }
    if (hadAttr) el.setAttribute(attrName, oldAttr);
    else el.removeAttribute(attrName);
    R.writeCell(opValue(ops, "cell"), codes.length - 1);
    resolve(codes.join(""));
   });
  });
 }
 function execEvPhaseFull(R, ops) {
  // Real event phases: a fresh three-node chain, listeners on the root
  // (capture 1, bubble 4) and the target (target phase, registration
  // order: capture-flag 2 then bubble 3). The bubble listener's side
  // effect (a dataset write) is read back after the dispatch, so the
  // entry proves the listener really ran in phase order.
  var id = bytesToAscii(opValue(ops, "id"));
  if (!R.docIds[id]) return "none";
  var host = R.doc.getElementById(id);
  if (!host) return "none";
  var codes = [];
  var root = R.doc.createElement("div");
  var mid = R.doc.createElement("div");
  var target = R.doc.createElement("span");
  mid.appendChild(target);
  root.appendChild(mid);
  host.appendChild(root);
  var cap = function () { codes.push(1); };
  var tcap = function () { codes.push(2); };
  var tbub = function () {
   codes.push(3);
   try { target.dataset.kiwiphase = String(codes.length); } catch (e0) {}
  };
  var pbub = function () { codes.push(4); };
  root.addEventListener("kiwi-v6", cap, true);
  target.addEventListener("kiwi-v6", tcap, true);
  target.addEventListener("kiwi-v6", tbub, false);
  root.addEventListener("kiwi-v6", pbub, false);
  var ds = "";
  try {
   target.dispatchEvent(new R.doc.defaultView.Event("kiwi-v6", { bubbles: true }));
   ds = target.dataset.kiwiphase || "";
  } catch (e1) { ds = ""; }
  root.removeEventListener("kiwi-v6", cap, true);
  target.removeEventListener("kiwi-v6", tcap, true);
  target.removeEventListener("kiwi-v6", tbub, false);
  root.removeEventListener("kiwi-v6", pbub, false);
  host.removeChild(root);
  R.writeCell(opValue(ops, "cell"), codes.length);
  return codes.join("") + ":" + ds;
 }
 function execRangeOrder(R, ops) {
  // Range and Selection over a constructed text graph: a fresh narrow
  // container holds three span words, the drawn range crosses all three
  // text nodes, and the entry reports the exact range string length,
  // the line-box fragment count of getClientRects and the Selection
  // range count after addRange.
  var id = bytesToAscii(opValue(ops, "id"));
  if (!R.docIds[id]) return "none";
  var host = R.doc.getElementById(id);
  if (!host) return "none";
  var ra = opValue(ops, "ra"), rb = opValue(ops, "rb");
  var container = R.doc.createElement("div");
  container.style.cssText = "display:block;width:48px;font-size:12px;font-family:monospace;line-height:normal;";
  var spans = [];
  for (var s = 0; s < 3; s++) {
   var sp = R.doc.createElement("span");
   sp.textContent = RANGE_WORDS[(ra + s) % RANGE_WORDS.length];
   container.appendChild(sp);
   spans.push(sp);
  }
  host.appendChild(container);
  var a = ra % 5;
  var w2 = RANGE_WORDS[(ra + 2) % RANGE_WORDS.length];
  var e = rb % (w2.length + 1);
  var value;
  try {
   var range = R.doc.createRange();
   range.setStart(spans[0].firstChild, a);
   range.setEnd(spans[2].firstChild, e);
   var t = range.toString().length;
   var rects = range.getClientRects().length;
   if (!isFinite(rects) || rects < 0) rects = 0;
   if (rects > 255) rects = 255;
   var sel = R.doc.defaultView.getSelection();
   var sc = 0;
   if (sel) {
    try {
     sel.removeAllRanges();
     sel.addRange(range);
     sc = sel.rangeCount;
     sel.removeAllRanges();
    } catch (e1) { sc = 0; }
   }
   value = t + "," + rects + "," + sc;
   R.writeCell(opValue(ops, "cell"), rects);
  } catch (e2) {
   value = "0";
  }
  host.removeChild(container);
  return value;
 }
 function execIntObs(R, ops) {
  // IntersectionObserver thresholds: a fresh root box (120x40, clipped)
  // holds a 60x20 target at the seed-drawn offset, so the observed
  // intersection ratio is a real layout quantity. The entry reports the
  // delivered-entry count, the quantized ratio and isIntersecting after
  // two animation frames (or the fallback timeout) let the observer
  // deliver its initial threshold state.
  return new Promise(function (resolve) {
   var id = bytesToAscii(opValue(ops, "id"));
   if (!R.docIds[id]) { resolve("none"); return; }
   var host = R.doc.getElementById(id);
   if (!host) { resolve("none"); return; }
   var seed = opValue(ops, "seed");
   var m = 5 + (seed % 36);
   var t0 = [0, 0.25, 0.5, 0.75][seed % 4];
   var root = R.doc.createElement("div");
   root.style.cssText = "position:relative;width:120px;height:40px;overflow:hidden;";
   var tgt = R.doc.createElement("div");
   tgt.style.cssText = "width:60px;height:20px;margin-top:" + m + "px;";
   root.appendChild(tgt);
   host.appendChild(root);
   var fired = 0, q = 0, isInt = 0;
   var io;
   try {
    io = new IntersectionObserver(function (entries) {
     if (!fired && entries.length > 0) {
      fired = 1;
      var ratio = entries[0].intersectionRatio;
      if (!isFinite(ratio) || ratio < 0) ratio = 0;
      q = Math.round(ratio * 100);
      if (q > 100) q = 100;
      isInt = entries[0].isIntersecting ? 1 : 0;
     }
    }, { root: root, threshold: [t0] });
    io.observe(tgt);
   } catch (e0) {
    host.removeChild(root);
    resolve("0");
    return;
   }
   var view = R.doc.defaultView;
   function nextFrame(fn) {
    var settledFrame = false;
    var fin = function () {
     if (settledFrame) return;
     settledFrame = true;
     fn();
    };
    try { view.requestAnimationFrame(function () { view.requestAnimationFrame(fin); }); } catch (e1) {}
    setTimeout(fin, 250);
   }
   nextFrame(function () {
    nextFrame(function () {
     io.disconnect();
     host.removeChild(root);
     R.writeCell(opValue(ops, "cell"), q);
     resolve(fired + "," + q + "," + isInt);
    });
   });
  });
 }
 // ── The digest ──
 function computeDigest(programBytes, program, nonce, trace) {
  var msg = asciiBytes(
   KIWI_EXECUTION_PROTOCOL + "|" + nonce + "|" + program.scope + "|" +
   program.action + "|" + program.opVersion + "|" + trace
  );
  return bytesToHex(hmacSha256(programBytes, msg));
 }
 // ── The message loop ──
 function start() {
  if (typeof window === "undefined" || !window.parent) return;
  var parent = window.parent;
  function post(type, payload) {
   try {
    // The srcdoc iframe is same-origin: "/" (the sender-origin shorthand)
    // reaches the real parent; the literal "null" origin reported here drops it.
    parent.postMessage({ type: type, protocol: KIWI_EXECUTION_PROTOCOL, payload: payload || {} }, "/");
   } catch (e) {}
  }
  window.addEventListener("message", function (event) {
   // Only the embedding parent may start a run: a sibling frame (or any
   // other window holding this iframe's reference) posting forged run
   // traffic is ignored — the mirror of the parent-side
   // event.source === iframe.contentWindow gate. The about:srcdoc
   // document serializes its own location.origin as "null", so the
   // origin comparison reads the parent's; an unreadable parent origin
   // is a foreign origin and fails closed.
   var parentOrigin = null;
   try { parentOrigin = window.parent.location.origin; } catch (e) {}
   if (event.source !== parent || parentOrigin === null || event.origin !== parentOrigin) {
    return;
   }
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
   if (trace && typeof trace.then === "function") {
    // A version-6 run resolves a few microtasks and animation frames
    // later (the platform probes await real delivery); the result
    // message still carries the identical digest-plus-trace payload.
    trace.then(function (settled) {
     post(KIWI_EXECUTION_RESULT, { id: id, digest: computeDigest(programBytes, program, nonce, settled), trace: settled });
    }, function () {
     post(KIWI_EXECUTION_ERROR, { id: id, reason: "program-execution" });
    });
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
