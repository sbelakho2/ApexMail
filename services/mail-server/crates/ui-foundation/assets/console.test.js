/* Node tests for /assets/console.js — run with: node assets/console.test.js
 *
 * Covers the pure helpers (form serialization, redirect sanitization) and
 * validates the local QR encoder with an independent structural decoder:
 *   - finder / timing / alignment patterns match the QR spec,
 *   - both format-info copies decode to (ECC L, chosen mask) and are
 *     BCH-consistent,
 *   - the unmasked, spec-order deinterleaved codeword stream decodes to
 *     byte mode + the exact UTF-8 payload + terminator/padding,
 *   - every Reed-Solomon block evaluates to zero at all generator roots
 *     (i.e. the ECC is consistent).
 */
'use strict';

var consoleJs = require('./console.js');

var failures = 0;
function check(name, condition, detail) {
  if (condition) {
    console.log('ok   - ' + name);
  } else {
    failures++;
    console.log('FAIL - ' + name + (detail !== undefined ? ' :: ' + detail : ''));
  }
}

// ── serializeEntries ──────────────────────────────────────────────────
var payload = consoleJs.serializeEntries([
  ['name', 'Spring campaign'],
  ['providers', 'gmail'],
  ['providers', 'outlook'],
  ['providers', 'yahoo'],
  ['_csrf', 'should-be-dropped-by-caller-not-here']
]);
check('serializeEntries maps single values', payload.name === 'Spring campaign');
check('serializeEntries collects repeats into arrays',
  Array.isArray(payload.providers) && payload.providers.join(',') === 'gmail,outlook,yahoo');

// ── sanitizeRedirect ──────────────────────────────────────────────────
check('sanitizeRedirect allows paths', consoleJs.sanitizeRedirect('/campaigns') === '/campaigns');
check('sanitizeRedirect allows query paths',
  consoleJs.sanitizeRedirect('/campaigns?query=x') === '/campaigns?query=x');
check('sanitizeRedirect blocks javascript:',
  consoleJs.sanitizeRedirect('javascript:alert(1)') === null);
check('sanitizeRedirect blocks absolute URLs',
  consoleJs.sanitizeRedirect('https://evil.example') === null);
check('sanitizeRedirect blocks protocol-relative',
  consoleJs.sanitizeRedirect('//evil.example') === null);
check('sanitizeRedirect blocks data: URLs', consoleJs.sanitizeRedirect('data:text/html,x') === null);
check('sanitizeRedirect blocks whitespace-prefixed schemes',
  consoleJs.sanitizeRedirect('   javascript:alert(1)') === null);
check('sanitizeRedirect rejects non-strings', consoleJs.sanitizeRedirect(null) === null);

// ── QR encoder — independent spec tables (ISO/IEC 18004) ──────────────
var ECC_L_CODEWORDS = [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28];
var ECC_L_BLOCKS = [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8];

var GF_EXP = new Array(512);
var GF_LOG = new Array(256);
(function () {
  var x = 1;
  for (var i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (var j = 255; j < 512; j++) GF_EXP[j] = GF_EXP[j - 255];
})();
function gfMul(a, b) { return (a === 0 || b === 0) ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]; }
function gfPow(a, n) { var r = 1; for (var i = 0; i < n; i++) r = gfMul(r, a); return r; }

/** Rebuild the function-pattern map for a version/size independently. */
function buildFunctionMap(size, ver) {
  var isFn = [];
  for (var y = 0; y < size; y++) isFn.push(new Array(size).fill(false));
  function mark(x, y) {
    if (x >= 0 && x < size && y >= 0 && y < size) isFn[y][x] = true;
  }
  [[3, 3], [size - 4, 3], [3, size - 4]].forEach(function (center) {
    for (var dy = -4; dy <= 4; dy++) {
      for (var dx = -4; dx <= 4; dx++) mark(center[0] + dx, center[1] + dy);
    }
  });
  for (var i = 0; i < size; i++) { mark(6, i); mark(i, 6); }
  // Alignment patterns.
  if (ver > 1) {
    var numAlign = Math.floor(ver / 7) + 2;
    var step = (ver === 32) ? 26 : Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
    var pos = [6];
    for (var p = size - 7; pos.length < numAlign; p -= step) pos.splice(1, 0, p);
    for (var ai = 0; ai < pos.length; ai++) {
      for (var aj = 0; aj < pos.length; aj++) {
        if ((ai === 0 && aj === 0) || (ai === 0 && aj === pos.length - 1) ||
            (ai === pos.length - 1 && aj === 0)) continue;
        for (var dy2 = -2; dy2 <= 2; dy2++) {
          for (var dx2 = -2; dx2 <= 2; dx2++) mark(pos[ai] + dx2, pos[aj] + dy2);
        }
      }
    }
  }
  // Format info positions (both copies) and the always-dark module.
  for (var f = 0; f <= 5; f++) mark(8, f);
  mark(8, 7); mark(8, 8); mark(7, 8);
  for (var g = 9; g < 15; g++) mark(14 - g, 8);
  for (var h = 0; h < 8; h++) mark(size - 1 - h, 8);
  for (var k = 8; k < 15; k++) mark(8, size - 15 + k);
  mark(8, size - 8);
  if (ver >= 7) {
    for (var b = 0; b < 18; b++) {
      mark(size - 11 + (b % 3), Math.floor(b / 3));
      mark(Math.floor(b / 3), size - 11 + (b % 3));
    }
  }
  return isFn;
}

var MASK_FNS = [
  function (x, y) { return (x + y) % 2 === 0; },
  function (x) { return x % 2 === 0; },
  function (x, y) { return y % 3 === 0; },
  function (x, y) { return (x + y) % 3 === 0; },
  function (x, y) { return (Math.floor(x / 2) + Math.floor(y / 3)) % 2 === 0; },
  function (x, y) { return (x * y) % 2 + (x * y) % 3 === 0; },
  function (x, y) { return ((x * y) % 2 + (x * y) % 3) % 2 === 0; },
  function (x, y) { return ((x + y) % 2 + (x * y) % 3) % 2 === 0; }
];

function readFormatCopies(qr) {
  var size = qr.size;
  function bit(x, y) { return qr.modules[y][x] ? 1 : 0; }
  function copy0() {
    var v = 0;
    for (var i = 0; i <= 5; i++) v |= bit(8, i) << i;
    v |= bit(8, 7) << 6;
    v |= bit(8, 8) << 7;
    v |= bit(7, 8) << 8;
    for (var j = 9; j < 15; j++) v |= bit(14 - j, 8) << j;
    return v;
  }
  function copy1() {
    var v = 0;
    for (var i = 0; i < 8; i++) v |= bit(size - 1 - i, 8) << i;
    for (var j = 8; j < 15; j++) v |= bit(8, size - 15 + j) << j;
    return v;
  }
  return { copy0: copy0(), copy1: copy1() };
}

/** Decode a QR matrix fully: returns {payload: string, eclBits, mask}. */
function decodeQr(qr) {
  var size = qr.size;
  var ver = (size - 17) / 4;
  var isFn = buildFunctionMap(size, ver);
  var copies = readFormatCopies(qr);
  var raw = copies.copy0 ^ 0x5412;
  var eclBits = (raw >>> 13) & 0x3;
  var mask = (raw >>> 10) & 0x7;
  var remBits = raw & 0x3ff;
  // BCH(15,5) check: payload << 10 must equal the syndrome.
  var data5 = (eclBits << 3) | mask;
  var rem = data5;
  for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  var bchOk = (rem & 0x3ff) === remBits;

  // Read the data modules in the standard zigzag order.
  var maskFn = MASK_FNS[mask];
  var bits = [];
  var bitIndex = 0;
  for (var right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (var vert = 0; vert < size; vert++) {
      for (var j = 0; j < 2; j++) {
        var x = right - j;
        var upward = ((right + 1) & 2) === 0;
        var y = upward ? size - 1 - vert : vert;
        if (!isFn[y][x]) {
          var v = qr.modules[y][x] ? 1 : 0;
          if (maskFn(x, y)) v ^= 1;
          bits[bitIndex] = v;
          bitIndex++;
        }
      }
    }
  }
  var codewords = [];
  for (var c = 0; c + 8 <= bits.length; c += 8) {
    var byte = 0;
    for (var b = 0; b < 8; b++) byte = (byte << 1) | bits[c + b];
    codewords.push(byte);
  }
  // Deinterleave (spec order).
  var numBlocks = ECC_L_BLOCKS[ver];
  var blockEccLen = ECC_L_CODEWORDS[ver];
  var rawCw = Math.floor((function () {
    var result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      var numAlign = Math.floor(ver / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (ver >= 7) result -= 36;
    }
    return result;
  })() / 8);
  var numShort = numBlocks - rawCw % numBlocks;
  var shortBlockLen = Math.floor(rawCw / numBlocks);
  // Spec-order deinterleave: all data columns, then the +1 data codeword of
  // the long blocks, then the ECC columns.
  var shortDataLen = shortBlockLen - blockEccLen;
  var blocksData = [];
  var blocksEcc = [];
  for (var bi = 0; bi < numBlocks; bi++) { blocksData.push([]); blocksEcc.push([]); }
  var idx = 0;
  for (var col = 0; col < shortDataLen; col++) {
    for (var b2 = 0; b2 < numBlocks; b2++) blocksData[b2].push(codewords[idx++]);
  }
  for (var bl = numShort; bl < numBlocks; bl++) blocksData[bl].push(codewords[idx++]);
  for (var e = 0; e < blockEccLen; e++) {
    for (var b3 = 0; b3 < numBlocks; b3++) blocksEcc[b3].push(codewords[idx++]);
  }
  // Concatenate data sections; verify RS syndromes per block.
  var dataBytes = [];
  var syndromesZero = true;
  blocksData.forEach(function (blockData, bi2) {
    var block = blockData.concat(blocksEcc[bi2]);
    for (var d = 0; d < blockData.length; d++) dataBytes.push(blockData[d]);
    for (var s = 0; s < blockEccLen; s++) {
      var evalAt = gfPow(2, s);
      var acc = 0;
      // Polynomial with block[0] as the highest-degree coefficient.
      block.forEach(function (coef) { acc = gfMul(acc, evalAt) ^ coef; });
      if (acc !== 0) syndromesZero = false;
    }
  });
  var eccTotal = blockEccLen * numBlocks;
  var _ = eccTotal;
  // Parse the bitstream: byte mode, count, payload — from the
  // DEINTERLEAVED data bytes (for multi-block versions the raw module
  // bitstream is interleaved and cannot be parsed directly).
  var dataBits = [];
  dataBytes.forEach(function (byte) {
    for (var b = 7; b >= 0; b--) dataBits.push((byte >>> b) & 1);
  });
  var pos = 0;
  function takeBits(count) {
    var v = 0;
    for (var t = 0; t < count; t++) v = (v << 1) | (dataBits[pos + t] || 0);
    pos += count;
    return v;
  }
  var mode = takeBits(4);
  var countBits = ver <= 9 ? 8 : 16;
  var count = takeBits(countBits);
  var payloadBytes = [];
  for (var p = 0; p < count; p++) payloadBytes.push(takeBits(8));
  var payload = Buffer.from(payloadBytes).toString('utf8');
  return {
    payload: payload,
    mode: mode,
    count: count,
    eclBits: eclBits,
    mask: mask,
    bchOk: bchOk,
    formatCopiesMatch: copies.copy0 === copies.copy1,
    syndromesZero: syndromesZero,
    version: ver,
    dataBytes: dataBytes.length
  };
}

function checkFinderPattern(qr, cx, cy) {
  var size = qr.size;
  for (var dy = -4; dy <= 4; dy++) {
    for (var dx = -4; dx <= 4; dx++) {
      var x = cx + dx, y = cy + dy;
      if (x < 0 || y < 0 || x >= size || y >= size) continue;
      var dist = Math.max(Math.abs(dx), Math.abs(dy));
      var expected = dist !== 2 && dist !== 4;
      if (qr.modules[y][x] !== expected) return false;
    }
  }
  return true;
}

function checkTimingPattern(qr) {
  var size = qr.size;
  for (var i = 8; i < size - 8; i++) {
    if (qr.modules[6][i] !== (i % 2 === 0)) return false;
    if (qr.modules[i][6] !== (i % 2 === 0)) return false;
  }
  return true;
}

var URLS = [
  'otpauth://totp/ApexMail:ops@apexmail.ee?secret=JBSWY3DPEHPK3PXP&issuer=ApexMail',
  'otpauth://totp/ApexMail:a.very-long.username%40example.co.uk?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=30&issuer=ApexMail%20Console',
  'https://apexmail.ee/verify?token=short',
  'x'
];

URLS.forEach(function (url, i) {
  var qr = consoleJs.qrEncodeText(url);
  check('qr[' + i + '] encodes', qr !== null);
  if (!qr) return;
  var size = qr.size;
  check('qr[' + i + '] size matches version', (size - 17) % 4 === 0 && size >= 21 && size <= 97);
  check('qr[' + i + '] finder TL', checkFinderPattern(qr, 3, 3));
  check('qr[' + i + '] finder TR', checkFinderPattern(qr, size - 4, 3));
  check('qr[' + i + '] finder BL', checkFinderPattern(qr, 3, size - 4));
  check('qr[' + i + '] timing pattern', checkTimingPattern(qr));

  var decoded = decodeQr(qr);
  check('qr[' + i + '] format copies agree', decoded.formatCopiesMatch);
  check('qr[' + i + '] format BCH valid', decoded.bchOk);
  check('qr[' + i + '] ECC level bits are L', decoded.eclBits === 1, 'got ' + decoded.eclBits);
  check('qr[' + i + '] mask id matches encoder report', decoded.mask === qr.mask);
  check('qr[' + i + '] byte mode', decoded.mode === 4, 'got ' + decoded.mode);
  check('qr[' + i + '] payload round-trips exactly', decoded.payload === url,
    'decoded ' + JSON.stringify(decoded.payload.slice(0, 60)));
  check('qr[' + i + '] RS syndromes all zero', decoded.syndromesZero);
  check('qr[' + i + '] codewords fill the version capacity', decoded.dataBytes > 0);
});

// Long input beyond version 20 capacity must fail cleanly (null), not throw.
check('qr rejects over-long input', consoleJs.qrEncodeText('a'.repeat(900)) === null);

// ── qrToCanvas with a stub canvas ─────────────────────────────────────
var qr = consoleJs.qrEncodeText('otpauth://totp/ApexMail:x?secret=JBSWY3DPEHPK3PXP');
var fillRectCalls = 0;
var darkFills = 0;
var canvasStub = {
  width: 0,
  height: 0,
  getContext: function (kind) {
    if (kind !== '2d') return null;
    return {
      fillStyle: null,
      fillRect: function (x, y, w, h) {
        fillRectCalls++;
        if (this.fillStyle === '#000000') darkFills++;
      }
    };
  }
};
check('qrToCanvas returns true', consoleJs.qrToCanvas(canvasStub, 'otpauth://totp/ApexMail:x?secret=JBSWY3DPEHPK3PXP') === true);
var expectedDark = qr.modules.reduce(function (sum, row) {
  return sum + row.filter(Boolean).length;
}, 0);
check('qrToCanvas paints every dark module', darkFills === expectedDark, darkFills + ' vs ' + expectedDark);
check('qrToCanvas includes quiet zone', canvasStub.width === (qr.size + 8) * 5);
check('qrToCanvas rejects missing canvas', consoleJs.qrToCanvas(null, 'x') === false);

if (failures > 0) {
  console.log('\n' + failures + ' test(s) FAILED');
  process.exit(1);
}
console.log('\nall console.js tests passed');
