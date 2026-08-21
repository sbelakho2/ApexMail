/* ApexMail console hydration script (/assets/console.js)
 *
 * Plain JavaScript, no build step, no external dependencies. Served as a
 * same-origin external file so the CSP (`script-src 'self'`) allows it with
 * no inline-script carve-outs. Pure helpers (form serialization, redirect
 * sanitization, the QR encoder) are exported for unit tests via
 * `module.exports` (Node) or `window.ApexMailConsole` (browser).
 *
 * Behaviors (each keyed by the data-* attributes the SSR HTML emits):
 *  - form[data-api-form]      serialize fields to JSON, POST to
 *                             data-api-action (or action) with the CSRF
 *                             header, redirect to data-redirect on success.
 *  - [data-alert-dialog-target]  open the referenced confirm dialog;
 *                             data-alert-dialog-cancel / -confirm close it;
 *                             Escape and backdrop clicks dismiss.
 *  - [data-view-state]        loading/ready/empty/error section toggling.
 *  - [data-rows-target] / [data-metric] / [data-bind] / [data-bind-list]
 *                             populate inbox-placement pages from
 *                             GET /v1/inbox-placement/tests[/:id].
 *  - header search button    mod+k focuses it; click prompts and navigates
 *                             to /campaigns?query=….
 *  - combobox (role=combobox) click/keyboard open-close-select toggle.
 *  - [data-theme-toggle]      aria-pressed initialization.
 *  - [data-copy-target]       copy-to-clipboard buttons (QR fallback).
 *  - ApexMailConsole.renderQr(canvas, text) — local, dependency-free QR
 *                             renderer (no third-party chart service).
 */
(function (global) {
  'use strict';

  // ── Pure helpers ─────────────────────────────────────────────────────

  /** Serialize [key, value] pairs (e.g. FormData entries) into a JSON
   * payload object. Repeated keys become arrays, preserving order. */
  function serializeEntries(pairs) {
    var payload = {};
    for (var i = 0; i < pairs.length; i++) {
      var key = pairs[i][0];
      var value = pairs[i][1];
      if (Object.prototype.hasOwnProperty.call(payload, key)) {
        if (!Array.isArray(payload[key])) payload[key] = [payload[key]];
        payload[key].push(value);
      } else {
        payload[key] = value;
      }
    }
    return payload;
  }

  /** Only allow same-origin path redirects — never javascript:, data:, or
   * cross-origin URLs from server- or markup-provided data-redirect values. */
  function sanitizeRedirect(dest) {
    if (typeof dest !== 'string') return null;
    var trimmed = dest.trim();
    if (trimmed === '' || trimmed.charAt(0) === '/') {
      // Reject protocol-relative and malformed scheme attempts like "//e".
      if (trimmed.charAt(1) === '/' && trimmed.charAt(0) === '/') return null;
      return trimmed;
    }
    return null;
  }

  // ── QR encoder (byte mode, ECC L, versions 1–20, mask penalty pick) ──
  // Compact implementation of the standard QR algorithm (structure follows
  // the well-known Nayuki reference generator, MIT licensed). Renders fully
  // client-side so TOTP secrets never leave the origin.

  var QR_ECC_CODEWORDS_PER_BLOCK_L = [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28];
  var QR_NUM_ECC_BLOCKS_L = [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8];
  var QR_MAX_VERSION = 20;

  function qrNumRawDataModules(ver) {
    var result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      var numAlign = Math.floor(ver / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (ver >= 7) result -= 36;
    }
    return result;
  }

  function qrDataCapacityBytes(ver) {
    return Math.floor(qrNumRawDataModules(ver) / 8) -
      QR_ECC_CODEWORDS_PER_BLOCK_L[ver] * QR_NUM_ECC_BLOCKS_L[ver];
  }

  function utf8Bytes(text) {
    var out = [];
    for (var i = 0; i < text.length; i++) {
      var code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        var lo = text.charCodeAt(i + 1);
        if (lo >= 0xdc00 && lo <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (lo - 0xdc00);
          i++;
        }
      }
      if (code < 0x80) {
        out.push(code);
      } else if (code < 0x800) {
        out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else if (code < 0x10000) {
        out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      } else {
        out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
    }
    return out;
  }

  var GF_EXP = new Array(512);
  var GF_LOG = new Array(256);
  (function initGf() {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      GF_EXP[i] = x;
      GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (var j = 255; j < 512; j++) GF_EXP[j] = GF_EXP[j - 255];
  })();
  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
  }

  function rsDivisor(degree) {
    var result = [];
    for (var i = 0; i < degree - 1; i++) result.push(0);
    result.push(1);
    var root = 1;
    for (var k = 0; k < degree; k++) {
      for (var j = 0; j < result.length; j++) {
        result[j] = gfMul(result[j], root);
        if (j + 1 < result.length) result[j] ^= result[j + 1];
      }
      root = gfMul(root, 0x02);
    }
    return result;
  }

  function rsRemainder(data, divisor) {
    var result = divisor.map(function () { return 0; });
    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ result.shift();
      result.push(0);
      divisor.forEach(function (coef, j) {
        result[j] ^= gfMul(coef, factor);
      });
    }
    return result;
  }

  function addEccAndInterleave(data, ver) {
    var numBlocks = QR_NUM_ECC_BLOCKS_L[ver];
    var blockEccLen = QR_ECC_CODEWORDS_PER_BLOCK_L[ver];
    var rawCodewords = Math.floor(qrNumRawDataModules(ver) / 8);
    var numShortBlocks = numBlocks - rawCodewords % numBlocks;
    var shortBlockLen = Math.floor(rawCodewords / numBlocks);
    var divisor = rsDivisor(blockEccLen);
    var blocks = [];
    var k = 0;
    for (var b = 0; b < numBlocks; b++) {
      var dat = data.slice(k, k + shortBlockLen - blockEccLen + (b < numShortBlocks ? 0 : 1));
      k += dat.length;
      var ecc = rsRemainder(dat, divisor);
      if (b < numShortBlocks) dat.push(0);
      blocks.push(dat.concat(ecc));
    }
    var result = [];
    for (var i = 0; i < blocks[0].length; i++) {
      for (var b2 = 0; b2 < blocks.length; b2++) {
        if (i !== shortBlockLen - blockEccLen || b2 >= numShortBlocks) {
          result.push(blocks[b2][i]);
        }
      }
    }
    return result;
  }

  function alignmentPositions(ver, size) {
    if (ver === 1) return [];
    var numAlign = Math.floor(ver / 7) + 2;
    var step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
    var positions = [6];
    for (var pos = size - 7; positions.length < numAlign; pos -= step) {
      positions.splice(1, 0, pos);
    }
    return positions;
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

  function calcFormatBits(mask) {
    var ecl = 1; // ECC level L
    var data = (ecl << 3) | mask;
    var rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    return ((data << 10) | rem) ^ 0x5412;
  }

  /** Encode `text` into a QR matrix ({size, mask, modules[][]}) or null.
   * Exposed for tests: qrEncodeCodewords returns the intermediate codeword
   * stream (data codewords, then data+ecc interleaved) plus the version. */
  function qrEncodeCodewords(text) {
    var bytes = utf8Bytes(String(text));
    var ver, capacity;
    for (ver = 1; ver <= QR_MAX_VERSION; ver++) {
      capacity = qrDataCapacityBytes(ver);
      var countBits = ver <= 9 ? 8 : 16;
      if (4 + countBits + bytes.length * 8 <= capacity * 8) break;
    }
    if (ver > QR_MAX_VERSION) return null;

    // Bit buffer: mode 0100, count, payload, terminator, byte pad, 0xEC/0x11.
    var bits = [];
    function appendBits(value, len) {
      for (var i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
    }
    appendBits(4, 4);
    appendBits(bytes.length, ver <= 9 ? 8 : 16);
    bytes.forEach(function (b) { appendBits(b, 8); });
    var capacityBits = capacity * 8;
    appendBits(0, Math.min(4, capacityBits - bits.length));
    appendBits(0, (8 - bits.length % 8) % 8);
    for (var pad = 0xec; bits.length < capacityBits; pad ^= 0xec ^ 0x11) {
      appendBits(pad, 8);
    }
    var dataCodewords = [];
    for (var c = 0; c < bits.length; c += 8) {
      var byte = 0;
      for (var j = 0; j < 8; j++) byte = (byte << 1) | bits[c + j];
      dataCodewords.push(byte);
    }
    return {
      version: ver,
      dataCodewords: dataCodewords,
      allCodewords: addEccAndInterleave(dataCodewords, ver)
    };
  }

  function qrEncodeText(text) {
    var encoded = qrEncodeCodewords(text);
    if (!encoded) return null;
    return drawMatrix(encoded.allCodewords, encoded.version);
  }

  function drawMatrix(codewords, ver) {
    var size = ver * 4 + 17;
    var modules = [];
    var isFunction = [];
    for (var r = 0; r < size; r++) {
      modules.push(new Array(size).fill(false));
      isFunction.push(new Array(size).fill(false));
    }
    function setFunctionModule(x, y, dark) {
      if (x < 0 || y < 0 || x >= size || y >= size) return;
      modules[y][x] = dark;
      isFunction[y][x] = true;
    }
    function drawFinderPattern(x, y) {
      for (var dy = -4; dy <= 4; dy++) {
        for (var dx = -4; dx <= 4; dx++) {
          var dist = Math.max(Math.abs(dx), Math.abs(dy));
          setFunctionModule(x + dx, y + dy, dist !== 2 && dist !== 4);
        }
      }
    }
    function drawAlignmentPattern(x, y) {
      for (var dy = -2; dy <= 2; dy++) {
        for (var dx = -2; dx <= 2; dx++) {
          setFunctionModule(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
    // Timing patterns.
    for (var i = 0; i < size; i++) {
      setFunctionModule(6, i, i % 2 === 0);
      setFunctionModule(i, 6, i % 2 === 0);
    }
    drawFinderPattern(3, 3);
    drawFinderPattern(size - 4, 3);
    drawFinderPattern(3, size - 4);
    var alignPatPos = alignmentPositions(ver, size);
    var numAlign = alignPatPos.length;
    for (var ai = 0; ai < numAlign; ai++) {
      for (var aj = 0; aj < numAlign; aj++) {
        if (!(ai === 0 && aj === 0) && !(ai === 0 && aj === numAlign - 1) && !(ai === numAlign - 1 && aj === 0)) {
          drawAlignmentPattern(alignPatPos[ai], alignPatPos[aj]);
        }
      }
    }
    // Reserve format modules with a dummy mask; real bits after mask choice.
    drawFormatBits(0);
    if (ver >= 7) drawVersion(ver);

    function drawFormatBits(mask) {
      var dataBits = calcFormatBits(mask);
      function bit(i) { return ((dataBits >>> i) & 1) !== 0; }
      for (var f = 0; f <= 5; f++) setFunctionModule(8, f, bit(f));
      setFunctionModule(8, 7, bit(6));
      setFunctionModule(8, 8, bit(7));
      setFunctionModule(7, 8, bit(8));
      for (var g = 9; g < 15; g++) setFunctionModule(14 - g, 8, bit(g));
      for (var h = 0; h < 8; h++) setFunctionModule(size - 1 - h, 8, bit(h));
      for (var k2 = 8; k2 < 15; k2++) setFunctionModule(8, size - 15 + k2, bit(k2));
      setFunctionModule(8, size - 8, true);
    }
    function drawVersion(v) {
      var rem = v;
      for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      var bitsData = (v << 12) | rem;
      for (var b = 0; b < 18; b++) {
        var isDark = ((bitsData >>> b) & 1) !== 0;
        var a = size - 11 + (b % 3);
        var q = Math.floor(b / 3);
        setFunctionModule(a, q, isDark);
        setFunctionModule(q, a, isDark);
      }
    }

    function applyMask(mask) {
      var fn = MASK_FNS[mask];
      for (var y = 0; y < size; y++) {
        for (var x = 0; x < size; x++) {
          if (!isFunction[y][x] && fn(x, y)) modules[y][x] = !modules[y][x];
        }
      }
    }

    // Place codewords (zigzag from the right, skipping column 6).
    var bitIndex = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        for (var dj = 0; dj < 2; dj++) {
          var x = right - dj;
          var upward = ((right + 1) & 2) === 0;
          var y = upward ? size - 1 - vert : vert;
          if (!isFunction[y][x] && bitIndex < codewords.length * 8) {
            modules[y][x] = ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) !== 0;
          }
          if (!isFunction[y][x]) {
            bitIndex++;
            // XOR mask applied later via applyMask for selection.
          }
        }
      }
    }

    function penaltyScore() {
      var result = 0, x2, y2;
      // Rule 1: runs of 5+ same color.
      for (y2 = 0; y2 < size; y2++) {
        var runColor = false, runX = 0;
        for (x2 = 0; x2 < size; x2++) {
          if (modules[y2][x2] === runColor) {
            runX++;
            if (runX === 5) result += 3;
            else if (runX > 5) result++;
          } else {
            runColor = modules[y2][x2];
            runX = 1;
          }
        }
      }
      for (x2 = 0; x2 < size; x2++) {
        var runC = false, runY = 0;
        for (y2 = 0; y2 < size; y2++) {
          if (modules[y2][x2] === runC) {
            runY++;
            if (runY === 5) result += 3;
            else if (runY > 5) result++;
          } else {
            runC = modules[y2][x2];
            runY = 1;
          }
        }
      }
      // Rule 2: 2x2 blocks.
      for (y2 = 0; y2 < size - 1; y2++) {
        for (x2 = 0; x2 < size - 1; x2++) {
          var c = modules[y2][x2];
          if (c === modules[y2][x2 + 1] && c === modules[y2 + 1][x2] && c === modules[y2 + 1][x2 + 1]) {
            result += 3;
          }
        }
      }
      // Rule 3: finder-like patterns (as binary string match).
      function rowStr(get) {
        var s = '';
        for (var idx = 0; idx < size; idx++) s += get(idx) ? '1' : '0';
        return s;
      }
      var pattern1 = '0000101110100001';
      var pattern2 = '10111010000';
      for (y2 = 0; y2 < size; y2++) {
        var rs = rowStr(function (idx) { return modules[y2][idx]; });
        var start = -1;
        while ((start = rs.indexOf(pattern2, start + 1)) !== -1) {
          if ((start === 0 || rs.charAt(start - 1) !== '1') && rs.indexOf('0000', start + 10) === start + 10) result += 40;
        }
        for (var p = rs.indexOf(pattern1); p !== -1; p = rs.indexOf(pattern1, p + 1)) result += 40;
      }
      for (x2 = 0; x2 < size; x2++) {
        var cs = rowStr(function (idx) { return modules[idx][x2]; });
        var start2 = -1;
        while ((start2 = cs.indexOf(pattern2, start2 + 1)) !== -1) {
          if ((start2 === 0 || cs.charAt(start2 - 1) !== '1') && cs.indexOf('0000', start2 + 10) === start2 + 10) result += 40;
        }
        for (var p2 = cs.indexOf(pattern1); p2 !== -1; p2 = cs.indexOf(pattern1, p2 + 1)) result += 40;
      }
      // Rule 4: dark proportion.
      var dark = 0;
      modules.forEach(function (row) {
        row.forEach(function (cell) { if (cell) dark++; });
      });
      var total = size * size;
      var k3 = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
      result += k3 * 10;
      return result;
    }

    // Choose the mask with the lowest penalty (draw/undo via double XOR).
    var mask = 0;
    var minPenalty = Infinity;
    for (var m = 0; m < 8; m++) {
      applyMask(m);
      var penalty = penaltyScore();
      applyMask(m);
      if (penalty < minPenalty) {
        minPenalty = penalty;
        mask = m;
      }
    }
    applyMask(mask);
    drawFormatBits(mask);

    return { size: size, mask: mask, modules: modules };
  }

  /** Draw an encoded QR matrix onto a canvas. Returns true on success. */
  function qrToCanvas(canvas, text, opts) {
    if (!canvas || !canvas.getContext) return false;
    var qr = qrEncodeText(text);
    if (!qr) return false;
    var scale = (opts && opts.scale) || 5;
    var border = 4; // quiet zone
    var dim = (qr.size + border * 2) * scale;
    canvas.width = dim;
    canvas.height = dim;
    var ctx = canvas.getContext('2d');
    if (!ctx) return false;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, dim, dim);
    ctx.fillStyle = '#000000';
    for (var y = 0; y < qr.size; y++) {
      for (var x = 0; x < qr.size; x++) {
        if (qr.modules[y][x]) {
          ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
        }
      }
    }
    return true;
  }

  // ── DOM hydration (browser only) ─────────────────────────────────────

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) return meta.content;
    var match = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
    var hidden = document.querySelector('form input[name="_csrf"]');
    if (match) return decodeURIComponent(match[1]);
    return hidden ? hidden.value : '';
  }

  function showFormError(form, message) {
    var box = form.querySelector('[role="alert"]');
    if (!box) {
      box = document.createElement('div');
      box.setAttribute('role', 'alert');
      box.className = 'mt-2 text-sm text-red-600 font-bold';
      form.appendChild(box);
    }
    box.textContent = message || 'Request failed.';
  }

  function submitApiForm(event) {
    var form = event.target;
    if (!form || form.dataset.apiBound === '1') return;
    event.preventDefault();
    var action = form.getAttribute('data-api-action') || form.getAttribute('action') || '';
    if (!action) return;
    var button = form.querySelector('[type="submit"]');
    if (button) {
      button.dataset.originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = 'Saving…';
    }
    var pairs = [];
    new FormData(form).forEach(function (value, key) {
      if (key !== '_csrf') pairs.push([key, value]);
    });
    form.querySelectorAll('[data-field]').forEach(function (el) {
      var name = el.getAttribute('data-field') || el.id;
      if (name && !pairs.some(function (pair) { return pair[0] === name; })) {
        pairs.push([name, el.getAttribute('data-value') !== null ? el.getAttribute('data-value') : el.value]);
      }
    });
    var payload = serializeEntries(pairs);
    var method = (form.getAttribute('data-api-method') || 'POST').toUpperCase();
    fetch(action, {
      method: method,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify(payload)
    })
      .then(function (resp) {
        return resp.json().then(function (data) { return { ok: resp.ok, status: resp.status, data: data }; })
          .catch(function () { return { ok: resp.ok, status: resp.status, data: null }; });
      })
      .then(function (result) {
        if (result.ok) {
          var dest = sanitizeRedirect(form.getAttribute('data-redirect'));
          if (!dest && action.indexOf('/v1/auth/') === 0) {
            if (action.indexOf('signup') !== -1 || action.indexOf('register') !== -1) dest = '/verify-email';
            else if (action.indexOf('login') !== -1) dest = '/dashboard';
            else if (action.indexOf('impersonate') !== -1) dest = '/cp';
          }
          if (dest) window.location.assign(dest);
        } else {
          var err = result.data && result.data.error;
          var msg = (err && (err.message || err.code)) || (result.data && result.data.message) ||
            ('Error (' + result.status + ')');
          showFormError(form, msg);
        }
      })
      .catch(function () { showFormError(form, 'Network error.'); })
      .finally(function () {
        if (button) {
          button.disabled = false;
          button.textContent = button.dataset.originalLabel || 'Submit';
        }
      });
  }

  function bindApiForms(root) {
    (root || document).querySelectorAll('form[data-api-form]').forEach(function (form) {
      if (form.dataset.apiBound === '1') return;
      form.dataset.apiBound = '1';
      form.addEventListener('submit', submitApiForm);
    });
  }

  function closeAlertDialog(dialog) {
    dialog.setAttribute('hidden', '');
    dialog.dataset.open = 'false';
  }

  function openAlertDialog(dialog) {
    dialog.removeAttribute('hidden');
    dialog.dataset.open = 'true';
    var focusTarget = dialog.querySelector('[data-initial-focus]') ||
      dialog.querySelector('[data-alert-dialog-confirm]') || dialog;
    if (focusTarget.focus) focusTarget.focus();
  }

  /** The confirm dialog markup is `div[id][hidden] > .fixed > [role=alertdialog]`.
   * Clicks deep inside need to resolve back to the outer wrapper. */
  function dialogWrapperFor(element) {
    var card = element.closest('[role="alertdialog"]');
    if (!card) return null;
    var overlay = card.parentElement;
    var wrapper = overlay ? overlay.parentElement : null;
    if (wrapper && wrapper.hasAttribute('id')) return wrapper;
    if (overlay && overlay.hasAttribute('id')) return overlay;
    return card;
  }

  function bindAlertDialogs() {
    var activeWrapper = null;
    document.addEventListener('click', function (event) {
      var target = event.target;
      var opener = target.closest && target.closest('[data-alert-dialog-target]');
      if (opener) {
        var dialog = document.getElementById(opener.getAttribute('data-alert-dialog-target'));
        if (dialog) {
          event.preventDefault();
          activeWrapper = dialog;
          openAlertDialog(dialog);
        }
        return;
      }
      var card = target.closest && target.closest('[role="alertdialog"]');
      if (!card) return;
      var wrapper = dialogWrapperFor(card) || card;
      if (target.closest('[data-alert-dialog-cancel]')) {
        event.preventDefault();
        closeAlertDialog(wrapper);
      } else if (target.closest('[data-alert-dialog-confirm]')) {
        event.preventDefault();
        var confirmedForm = wrapper.querySelector('form');
        if (confirmedForm) {
          confirmedForm.dataset.apiBound = '';
          confirmedForm.submit();
        } else {
          wrapper.dispatchEvent(new CustomEvent('apexmail:dialog-confirm', { bubbles: true }));
        }
        closeAlertDialog(wrapper);
      } else if (target === wrapper.querySelector('.fixed')) {
        // Backdrop click dismisses.
        closeAlertDialog(wrapper);
      }
    });
    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') return;
      if (activeWrapper) {
        closeAlertDialog(activeWrapper);
        activeWrapper = null;
      }
    });
  }

  function setViewState(container, state) {
    container.querySelectorAll('[data-view-state]').forEach(function (section) {
      if (section.getAttribute('data-view-state') === state) {
        section.removeAttribute('hidden');
      } else {
        section.setAttribute('hidden', '');
      }
    });
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' }[c];
    });
  }

  function placementRowsHtml(test) {
    var status = String(test.status || 'pending').toLowerCase();
    var id = String(test.id || test.test_id || '');
    return '<tr>' +
      '<td class="px-6 py-3"><a class="text-primary hover:underline" href="/inbox-placement/' + encodeURIComponent(id) + '">' + escapeHtml(String(test.name || test.test_name || id)) + '</a></td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(test.from_email || test.from || '—')) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(status) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(test.score != null ? test.score : '—')) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(test.created_at || '—')) + '</td>' +
      '<td class="px-6 py-3 text-right"><a class="text-surface-600 hover:text-surface-900" href="/inbox-placement/' + encodeURIComponent(id) + '">Open</a></td>' +
      '</tr>';
  }

  function resultRowsHtml(result) {
    return '<tr>' +
      '<td class="px-6 py-3">' + escapeHtml(String(result.provider || result.provider_name || '—')) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(result.tested != null ? result.tested : '—')) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(result.inbox != null ? result.inbox : '—')) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(result.spam != null ? result.spam : '—')) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(result.missing != null ? result.missing : '—')) + '</td>' +
      '<td class="px-6 py-3">' + escapeHtml(String(result.inbox_rate != null ? result.inbox_rate : '—')) + '</td>' +
      '</tr>';
  }

  function fillRows(target, rowsHtml, emptyMessage) {
    target.innerHTML = rowsHtml ||
      '<tr data-empty-row><td class="px-6 py-12 text-center text-surface-500" colspan="6">' +
      escapeHtml(emptyMessage || 'No data.') + '</td></tr>';
  }

  function rate(value) {
    if (value == null) return '—';
    var num = Number(value);
    if (Number.isNaN(num)) return String(value);
    return (num <= 1 ? Math.round(num * 1000) / 10 : num) + '%';
  }

  function bindPlacementList(page) {
    var rowsTarget = page.querySelector('[data-rows-target="placement-tests"]');
    if (!rowsTarget) return;
    var meta = page.querySelector('[data-test-list-meta]');
    fetch('/v1/inbox-placement/tests', { credentials: 'same-origin' })
      .then(function (resp) { return resp.ok ? resp.json() : Promise.reject(new Error('HTTP ' + resp.status)); })
      .then(function (payload) {
        var tests = Array.isArray(payload) ? payload : (payload.tests || payload.items || payload.data || []);
        fillRows(rowsTarget, tests.map(placementRowsHtml).join(''),
          rowsTarget.getAttribute('data-empty-message'));
        var setMetric = function (key, value) {
          var el = page.querySelector('[data-metric="' + key + '"]');
          if (el) el.textContent = value;
        };
        setMetric('placement.total', String(tests.length));
        var withInbox = tests.filter(function (t) { return t.inbox_rate != null; });
        if (withInbox.length) {
          var avg = withInbox.reduce(function (sum, t) { return sum + Number(t.inbox_rate); }, 0) / withInbox.length;
          setMetric('placement.inbox_rate', rate(avg));
          var spam = tests.filter(function (t) { return t.spam_rate != null; });
          if (spam.length) {
            setMetric('placement.spam_rate', rate(spam.reduce(function (s, t) { return s + Number(t.spam_rate); }, 0) / spam.length));
          }
        }
        if (tests.length) {
          setMetric('placement.last_run', String(tests[0].created_at || tests[0].created || '—'));
        }
        if (meta) meta.textContent = tests.length + ' tests loaded';
        setViewState(page, 'ready');
      })
      .catch(function (err) {
        if (meta) meta.textContent = 'Failed to load: ' + err.message;
        setViewState(page, 'ready');
      });
  }

  function bindPlacementDetail(page) {
    var bindFields = page.querySelectorAll('[data-bind^="placement."]');
    if (!bindFields.length) return;
    var match = window.location.pathname.match(/\/inbox-placement\/([^/?#]+)/);
    var id = match ? decodeURIComponent(match[1]) : null;
    if (!id) return;
    fetch('/v1/inbox-placement/tests/' + encodeURIComponent(id), { credentials: 'same-origin' })
      .then(function (resp) { return resp.ok ? resp.json() : Promise.reject(new Error('HTTP ' + resp.status)); })
      .then(function (test) {
        test = test.test || test;
        var bind = function (key, value) {
          page.querySelectorAll('[data-bind="placement.' + key + '"]').forEach(function (el) {
            el.textContent = value;
          });
        };
        bind('test_name', String(test.name || test.test_name || id));
        bind('subject', String(test.subject || '—'));
        bind('from_email', String(test.from_email || test.from || '—'));
        bind('status', String(test.status || 'pending'));
        bind('score', String(test.score != null ? test.score : '—'));
        bind('inbox_rate', rate(test.inbox_rate));
        bind('spam_rate', rate(test.spam_rate));
        bind('missing_rate', rate(test.missing_rate));
        var rowsTarget = page.querySelector('[data-rows-target="placement-results"]');
        if (rowsTarget) {
          var results = test.results || test.providers || [];
          fillRows(rowsTarget, results.map(resultRowsHtml).join(''),
            rowsTarget.getAttribute('data-empty-message'));
        }
        var list = page.querySelector('[data-bind-list="placement.recommendations"]');
        if (list) {
          var recs = test.recommendations || [];
          list.innerHTML = '';
          if (!recs.length) {
            var li = document.createElement('li');
            li.className = 'text-surface-500';
            li.textContent = list.getAttribute('data-empty-message') || 'No recommendations available.';
            list.appendChild(li);
          } else {
            recs.forEach(function (rec) {
              var item = document.createElement('li');
              item.textContent = typeof rec === 'string' ? rec : JSON.stringify(rec);
              list.appendChild(item);
            });
          }
        }
        setViewState(page, 'ready');
      })
      .catch(function () { setViewState(page, 'ready'); });
  }

  function bindSearch() {
    var button = document.querySelector('button[data-shortcut="mod+k"]');
    if (!button || button.dataset.searchBound === '1') return;
    button.dataset.searchBound = '1';
    button.addEventListener('click', function () {
      var query = window.prompt('Search campaigns');
      if (query != null && query.trim() !== '') {
        window.location.assign('/campaigns?query=' + encodeURIComponent(query.trim()));
      }
    });
    document.addEventListener('keydown', function (event) {
      var mod = event.metaKey || event.ctrlKey;
      if (mod && (event.key === 'k' || event.key === 'K')) {
        event.preventDefault();
        button.focus();
        button.click();
      }
    });
  }

  function bindSelects() {
    document.addEventListener('click', function (event) {
      var trigger = event.target.closest && event.target.closest('button[role="combobox"]');
      if (trigger) {
        var wrapper = trigger.parentElement;
        var menu = wrapper.querySelector('[role="listbox"]');
        var open = wrapper.getAttribute('data-open') === 'true';
        wrapper.setAttribute('data-open', open ? 'false' : 'true');
        trigger.setAttribute('aria-expanded', open ? 'false' : 'true');
        if (menu) {
          if (open) menu.setAttribute('hidden', '');
          else menu.removeAttribute('hidden');
        }
        return;
      }
      var option = event.target.closest && event.target.closest('[role="option"]');
      if (option && !option.hasAttribute('data-disabled')) {
        var listbox = option.closest('[role="listbox"]');
        var selectWrapper = listbox && listbox.parentElement;
        if (selectWrapper && selectWrapper.querySelector('button[role="combobox"]')) {
          var label = option.querySelector('span:last-of-type') || option;
          var triggerBtn = selectWrapper.querySelector('button[role="combobox"]');
          var triggerLabel = triggerBtn.querySelector('span');
          if (triggerLabel) triggerLabel.textContent = label.textContent;
          listbox.querySelectorAll('[role="option"]').forEach(function (o) {
            o.setAttribute('aria-selected', o === option ? 'true' : 'false');
          });
          // Surface the selection for data-api-form serialization.
          var value = option.getAttribute('data-value');
          if (value === null) value = label.textContent;
          var fieldEl = selectWrapper.querySelector('[data-field]');
          var fieldName = selectWrapper.getAttribute('data-field') ||
            (fieldEl ? fieldEl.getAttribute('data-field') : null);
          if (fieldName) selectWrapper.setAttribute('data-value', value);
          selectWrapper.setAttribute('data-open', 'false');
          triggerBtn.setAttribute('aria-expanded', 'false');
          listbox.setAttribute('hidden', '');
          triggerBtn.focus();
        }
      }
    });
    document.addEventListener('keydown', function (event) {
      var trigger = event.target.closest && event.target.closest('button[role="combobox"]');
      if (!trigger) return;
      var wrapper = trigger.parentElement;
      var listbox = wrapper.querySelector('[role="listbox"]');
      var options = listbox ? Array.prototype.slice.call(listbox.querySelectorAll('[role="option"]')) : [];
      if (!options.length) return;
      var activeIndex = options.findIndex(function (o) { return o.getAttribute('aria-selected') === 'true'; });
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        var next = (activeIndex + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length;
        trigger.setAttribute('aria-activedescendant', options[next].id);
        options[next].focus && options[next].focus();
      } else if (event.key === 'Enter') {
        event.preventDefault();
        options[Math.max(activeIndex, 0)].click();
      } else if (event.key === 'Escape') {
        wrapper.setAttribute('data-open', 'false');
        trigger.setAttribute('aria-expanded', 'false');
        if (listbox) listbox.setAttribute('hidden', '');
      }
    });
  }

  function initThemeAria() {
    var button = document.querySelector('[data-theme-toggle]');
    if (!button) return;
    var isDark = document.documentElement.classList.contains('dark');
    button.setAttribute('aria-pressed', isDark ? 'true' : 'false');
  }

  function bindCopyButtons() {
    document.addEventListener('click', function (event) {
      var button = event.target.closest && event.target.closest('[data-copy-target]');
      if (!button) return;
      var source = document.getElementById(button.getAttribute('data-copy-target'));
      if (!source) return;
      var text = source.getAttribute('data-copy-value') || source.textContent || '';
      var done = function () {
        var original = button.textContent;
        button.textContent = 'Copied!';
        window.setTimeout(function () { button.textContent = original; }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done);
      } else {
        var area = document.createElement('textarea');
        area.value = text;
        document.body.appendChild(area);
        area.select();
        try { document.execCommand('copy'); done(); } catch (err) { /* noop */ }
        document.body.removeChild(area);
      }
    });
  }

  function hydrate() {
    bindApiForms();
    bindAlertDialogs();
    bindSearch();
    bindSelects();
    initThemeAria();
    bindCopyButtons();
    var placementPage = document.querySelector('[data-page="inbox-placement"]');
    if (placementPage) bindPlacementList(placementPage);
    var detailPage = document.querySelector('[data-page="inbox-placement-detail"]');
    if (detailPage) bindPlacementDetail(detailPage);
    // Pages whose loading state has no dedicated fetch: reveal ready content
    // so SSR pages are never stuck behind a hidden loading section.
    document.querySelectorAll('[data-view-state="loading"]:not([hidden])').forEach(function (loading) {
      var scope = loading.parentElement;
      var hasReady = scope && scope.querySelector('[data-view-state="ready"]');
      if (hasReady) setViewState(scope, 'ready');
    });
  }

  var api = {
    serializeEntries: serializeEntries,
    sanitizeRedirect: sanitizeRedirect,
    qrEncodeText: qrEncodeText,
    qrEncodeCodewords: qrEncodeCodewords,
    qrToCanvas: qrToCanvas,
    hydrate: hydrate
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    global.ApexMailConsole = api;
    if (typeof document !== 'undefined') {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', hydrate);
      } else {
        hydrate();
      }
    }
  }
})(typeof window !== 'undefined' ? window : globalThis);
