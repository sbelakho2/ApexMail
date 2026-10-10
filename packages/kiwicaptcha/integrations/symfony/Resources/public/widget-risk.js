(function () {
  var encoder = new TextEncoder();
  var decoder = new TextDecoder();
  function kiwiRiskConfigValue(W, container, name) {
    // The eager core exposes the one configuration reader (widget element
    // wins over the container); fall back to the same order when the
    // module somehow runs without it.
    var bridge = (typeof window !== "undefined" && window.__kiwiCaptchaCore) || null;
    if (bridge && bridge.core && typeof bridge.core.configValue === "function") {
      return bridge.core.configValue(W, container, name);
    }
    var value = W && W.getAttribute ? W.getAttribute(name) : null;
    if ((value === null || value === "") && container && container !== W && container.getAttribute) value = container.getAttribute(name);
    return value;
  }
  // Solver protocol/ABI generation label, identical to the eager core's
  // literal (the spec asserts the copies agree) and verified by the worker
  // in its ready/done handshake; a stale cached worker is refused. This
  // pins driver+worker+wasm protocol compatibility only, never artifact
  // identity (that is the release tag + SHA256SUMS + SRI chain).
  var KIWI_SOLVER_PROTOCOL_ID = "2026-09-r1";
  // Bounded search cap, identical to the eager core's constant; the
  // worker enforces it there, the solve message carries it here.
  // The same search cap as the eager core: a 20-bit challenge exhausts at
  // e^-20 instead of the ~0.85% a 5M cap left at the top rung.
  var MAX_SHA_HASHES = 20000000;
  function b64decode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return Uint8Array.from(atob(str), function(c) { return c.charCodeAt(0); });
  }

  // ── The lazy risk tier ──────────────────────────────────────────────
  // Loaded ONLY when an armed response or configuration needs it: an
  // argon2id/rsw widget (adaptive solve tier), a server decoy field /
  // strategy hint, an execution_program, or a SHA-256 solve on a page
  // without the wasm glue (the files-tier worker dispatch). Files mode
  // injects this
  // module as a same-origin SRI-pinned script (native SRI fails closed);
  // inline mode embeds it. The module registers on the internal core
  // bridge and stays stateless: widget state is passed in per call.
  // Failure semantics: decoy/honeypot evidence is probabilistic, never a
  // gate (an unloadable module degrades to the absent default with a
  // console.warn); the argon2id/rsw/execution solve tiers fail closed
  // into the controlled
  // kiwi:worker-unavailable / kiwi:execution-unavailable states — never
  // a silent success, never a weaker-profile fallback; a SHA-256 solve
  // whose worker tier is missing degrades to the driver's in-page
  // pure-JS solver (the driver owns that fallback decision). The coarse
  // client-context descriptor moved into the eager core; this module
  // still reads it and bridge.core.boundBytes for decoy evidence.
  var kiwiExecutionRunCounter = 0;
  var KIWI_EXECUTION_TIMEOUT_MS = 10000;
  // Run one execution program in a fresh sandboxed ephemeral iframe and
  // resolve with the 64-hex digest, or reject with a reason (fail
  // closed). The iframe is removed after the run.
  function kiwiRunExecution(program, nonce, container, W) {
    return new Promise(function (resolve, reject) {
      // The one configuration reader: the widget element wins over the
      // container, exactly like every other data-kiwi-* attribute.
      var executionSrc = kiwiRiskConfigValue(W, container, "data-kiwi-execution-src");
      var executionIntegrity = kiwiRiskConfigValue(W, container, "data-kiwi-execution-integrity");
      if (!executionSrc || !executionIntegrity) {
        reject("execution-asset-unconfigured");
        return;
      }
      var iframe = document.createElement("iframe");
      // sandbox="allow-scripts allow-same-origin": a same-origin document
      // can remove its own sandbox attribute, so this is a confinement
      // boundary for the DISPOSABLE frame, not a security boundary
      // against the interpreter itself — the interpreter asset is the
      // SRI-pinned, content-addressed first-party code and the actual
      // trust anchor. (The frame is created per armed challenge, removed
      // after the run and never reused.)
      iframe.setAttribute("sandbox", "allow-scripts allow-same-origin");
      iframe.setAttribute("aria-hidden", "true");
      iframe.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden;";
      // allow-same-origin is required (an opaque-origin document cannot
      // load a same-origin script under the recommended CSP); the loaded
      // content is the SRI-pinned audited asset plus bytecode, never
      // untrusted code. The iframe is created per armed challenge and
      // removed after the run (a fresh document keeps the state machine
      // deterministic).
      iframe.srcdoc = "<!doctype html><html><head><meta charset=\"utf-8\"></head><body><script src=\"" +
        executionSrc.replace(/&/g, "&amp;").replace(/"/g, "&quot;") +
        "\" integrity=\"" + executionIntegrity.replace(/"/g, "&quot;") + "\"><\/script><\/body><\/html>";
      // The run message targets the iframe's same-origin window (never a
      // "*" target). The per-run id is channel hygiene; the authoritative
      // gate is the event.source === iframe.contentWindow check below.
      kiwiExecutionRunCounter = (kiwiExecutionRunCounter + 1) >>> 0;
      var runId = "kiwi-exec-" + kiwiExecutionRunCounter.toString(36) + "-" + nonce.slice(0, 8);
      var settled = false;
      var timeout = setTimeout(function () {
        if (settled) return;
        settled = true;
        cleanup();
        reject("execution-timeout");
      }, KIWI_EXECUTION_TIMEOUT_MS);
      var onMessage = function (event) {
        // Only the driver-created iframe may answer: forged page traffic
        // (event.source === the page window) is ignored.
        if (event.source !== iframe.contentWindow) return;
        var data = event.data;
        if (!data || !data.protocol || data.protocol !== "kiwi-execution-v1") return;
        if (data.type === "kiwi-execution-ready") {
          try {
            iframe.contentWindow.postMessage({
              type: "kiwi-execution-run",
              protocol: "kiwi-execution-v1",
              id: runId,
              program: program,
              nonce: nonce
            }, window.location.origin);
          } catch (e) { fail("execution-iframe"); }
          return;
        }
        if (data.type === "kiwi-execution-result" && data.payload && data.payload.id === runId) {
          var digest = data.payload.digest;
          var trace = data.payload.trace;
          if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
            fail("execution-digest-malformed");
            return;
          }
          if (typeof trace !== "string" || trace.length < 1 || trace.length > 8192) {
            fail("execution-trace-malformed");
            return;
          }
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          cleanup();
          resolve({ digest: digest, trace: trace });
          return;
        }
        if (data.type === "kiwi-execution-error" && data.payload && data.payload.id === runId) {
          fail("execution-interpreter-" + (data.payload.reason || "error"));
        }
      };
      function fail(reason) {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        cleanup();
        reject(reason);
      }
      function cleanup() {
        try { window.removeEventListener("message", onMessage); } catch (e) {}
        try { if (iframe.parentNode) iframe.parentNode.removeChild(iframe); } catch (e) {}
      }
      // The listener is attached BEFORE the iframe is appended, so the
      // ready handshake cannot be missed.
      window.addEventListener("message", onMessage);
      document.body.appendChild(iframe);
    });
  }

  // ── The same-origin worker solve tier ──────────────────────────────
  // The memory-hard and sequential time-lock solvers ALWAYS run off the
  // main thread; a missing/failed worker enters the controlled
  // kiwi:worker-unavailable state — no main-thread Argon2 hash and no
  // weaker-profile retry, ever. A SHA-256 solve also routes through
  // this tier when the page carries no wasm glue (files mode): the
  // worker solves it off the main thread, and the driver degrades a
  // missing/failed worker to the in-page pure-JS solver there (SHA-256
  // is main-thread-safe; the argon2id/rsw states stay fail-closed).
  // All postMessage traffic here is
  // worker-internal; forged page traffic is ignored (the spec asserts
  // forged payloads never mint a token). Inline mode builds the Blob
  // worker from the glue's embedded workerSource (zero requests);
  // files mode constructs a same-ORIGIN Worker from the fetched,
  // preflight-verified versioned asset (no Blob URL, so worker-src
  // 'self' suffices, never blob:); the legacy explicit data-kiwi-worker-
  // src URL keeps its direct-construction path. The worker never probes
  // an unversioned runtime: the driver always supplies the runtime URL
  // through the { type: "glue" } handshake below. The Blob URL of an
  // inline-mode worker is owned strictly by its own solve: the per-solve
  // teardown() revokes it on every terminal path, so two concurrent
  // solves never touch each other's URL (a page-global revoke here
  // would kill the FIRST widget's still-pending worker script fetch
  // when the SECOND widget created its worker).
  // ── Files-mode lazy asset loading (runtime + worker) ────────────────
  // In files mode the runtime glue and worker assets are fetched ONLY
  // when a challenge needs the worker tier (argon2id/rsw — or a
  // SHA-256 solve on a page without the wasm glue); both fetches are
  // bounded (two
  // retries), deduplicated per URL across the page, and preflight-
  // verified against the page-issued sha256 digests BEFORE the bytes are
  // used. The verification FAILS CLOSED: when a digest is demanded but
  // the page cannot compute it (no crypto.subtle.digest) the fetch is
  // refused with integrity-unverifiable — an unverifiable asset never
  // runs, and a mismatch never reaches the browser APIs.
  // Null-prototype caches: keys are asset URLs (page-influenced).
  var kiwiRuntimeGlueCache = Object.create(null);
  var kiwiWorkerAssetCache = Object.create(null);
  // The supported SRI digest algorithms: the crypto.subtle digest name
  // and the exact base64 length of each algorithm's output. A multi-hash
  // integrity attribute verifies against the first supported token.
  var KIWI_SRI_ALGOS = {
    "sha256-": { algo: "SHA-256", len: 44 },
    "sha384-": { algo: "SHA-384", len: 64 },
    "sha512-": { algo: "SHA-512", len: 88 },
  };
  var kiwiIntegrityWarned = false;
  function kiwiWarnIntegrityOff() {
    if (kiwiIntegrityWarned) return;
    kiwiIntegrityWarned = true;
    console.warn("KiwiCaptcha: asset URL carries no integrity digest; loading it unverified");
  }
  // Byte-exact preflight: the digest is computed over the EXACT fetched
  // bytes (never a re-encoded text form), and when the URL is
  // content-addressed (….<64-hex-sha256>.js) the embedded name must equal
  // the digest too — the same immutable URL the browser APIs then load is
  // therefore pinned to the verified bytes.
  function kiwiSha256B64ToHex(b64) {
    try {
      var bin = atob(b64);
      var hex = "";
      for (var i = 0; i < bin.length; i++) hex += ("0" + bin.charCodeAt(i).toString(16)).slice(-2);
      return hex;
    } catch (e) { return null; }
  }
  function kiwiVerifyIntegrityBytes(bytes, integrity, url) {
    if (!integrity) {
      var resolved = null;
      if (typeof url === "string" && url !== "") {
        try { resolved = new URL(url, window.location.href); } catch (e) {}
      }
      if (!resolved || resolved.origin !== window.location.origin) {
        return Promise.resolve({ ok: false, reason: "integrity-unconfigured" });
      }
      kiwiWarnIntegrityOff();
      return Promise.resolve({ ok: true });
    }
    var algo = null, expected = null;
    var tokens = String(integrity).split(/\s+/);
    for (var i = 0; i < tokens.length && !algo; i++) {
      for (var prefix in KIWI_SRI_ALGOS) {
        if (tokens[i].indexOf(prefix) === 0) {
          algo = KIWI_SRI_ALGOS[prefix];
          expected = tokens[i].slice(prefix.length);
          break;
        }
      }
    }
    if (!algo || expected.length !== algo.len || !/^[A-Za-z0-9+/]+={0,2}$/.test(expected)) {
      return Promise.resolve({ ok: false, reason: "integrity-malformed" });
    }
    if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.digest) {
      return Promise.resolve({ ok: false, reason: "integrity-unverifiable" });
    }
    var buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    return crypto.subtle.digest(algo.algo, buf).then(function (dig) {
      var out = new Uint8Array(dig);
      var bin = "";
      for (var i = 0; i < out.length; i++) bin += String.fromCharCode(out[i]);
      if (btoa(bin) !== expected) return { ok: false, reason: "integrity-mismatch" };
      if (algo.algo === "SHA-256" && typeof url === "string" && url !== "") {
        var m = url.match(/\.([0-9a-f]{64})\.(?:js|css)(?:[?#]|$)/);
        if (m && m[1] !== kiwiSha256B64ToHex(expected)) {
          return { ok: false, reason: "integrity-url-mismatch" };
        }
      }
      return { ok: true };
    }).catch(function () { return { ok: false, reason: "integrity-unverifiable" }; });
  }
  function kiwiFetchRuntimeGlue(url, integrity) {
    if (kiwiRuntimeGlueCache[url]) return kiwiRuntimeGlueCache[url];
    var promise = new Promise(function (resolve) {
      var attempt = 0;
      var lastReason = "runtime-unavailable";
      function tryFetch() {
        // A runtime URL WITHOUT a digest must never follow a redirect:
        // the requested URL's origin is not the origin of the served
        // bytes (a same-origin URL can 302 cross-origin). With a digest
        // the bytes stay SRI-pinned, so redirects are harmless.
        fetch(url, { cache: "force-cache", credentials: "same-origin", redirect: integrity ? "follow" : "error" })
          .then(function (r) {
            if (!r.ok) { lastReason = "runtime-fetch-" + r.status; throw new Error("KiwiCaptcha runtime fetch failed"); }
            var finalUrl = r.url || url;
            return r.arrayBuffer().then(function (buf) { return { bytes: new Uint8Array(buf), finalUrl: finalUrl }; });
          })
          .then(function (res) {
            var src = decoder.decode(res.bytes);
            if (src.indexOf("var KIWI_WASM_B64") === -1 || src.indexOf("__kiwiCaptchaWasm") === -1) {
              lastReason = "runtime-malformed";
              throw new Error("KiwiCaptcha runtime asset malformed");
            }
            return kiwiVerifyIntegrityBytes(res.bytes, integrity, res.finalUrl).then(function (vres) {
              if (!vres.ok) { lastReason = vres.reason; throw new Error("KiwiCaptcha runtime integrity failure"); }
              return src;
            });
          })
          .then(function (src) { resolve({ src: src }); })
          .catch(function () {
            if (attempt < 2) { attempt++; setTimeout(tryFetch, 250 * attempt); }
            else { resolve({ error: lastReason }); }
          });
      }
      tryFetch();
    });
    kiwiRuntimeGlueCache[url] = promise;
    // A terminal failure must never be cached for the page lifetime: an
    // explicit Retry after a transient network error has to fetch again.
    promise.then(function (res) { if (res && res.error) delete kiwiRuntimeGlueCache[url]; });
    return promise;
  }
  function kiwiFetchWorkerAsset(url, integrity) {
    if (kiwiWorkerAssetCache[url]) return kiwiWorkerAssetCache[url];
    var promise = new Promise(function (resolve) {
      var attempt = 0;
      var lastReason = "worker-unavailable";
      function tryFetch() {
        // Same transport contract as the runtime glue: a digest-less
        // worker asset never follows a redirect; with a digest the
        // fetched bytes are SRI-pinned.
        fetch(url, { cache: "force-cache", credentials: "same-origin", redirect: integrity ? "follow" : "error" })
          .then(function (r) {
            if (!r.ok) { lastReason = "worker-fetch-" + r.status; throw new Error("KiwiCaptcha worker asset fetch failed"); }
            var finalUrl = r.url || url;
            return r.arrayBuffer().then(function (buf) { return { bytes: new Uint8Array(buf), finalUrl: finalUrl }; });
          })
          .then(function (res) {
            var src = decoder.decode(res.bytes);
            if (src.indexOf("KiwiCaptcha worker solver") === -1) {
              lastReason = "worker-malformed";
              throw new Error("KiwiCaptcha worker asset malformed");
            }
            return kiwiVerifyIntegrityBytes(res.bytes, integrity, res.finalUrl).then(function (vres) {
              if (!vres.ok) { lastReason = vres.reason; throw new Error("KiwiCaptcha worker integrity failure"); }
              return src;
            });
          })
          .then(function (src) { resolve({ src: src }); })
          .catch(function () {
            if (attempt < 2) { attempt++; setTimeout(tryFetch, 250 * attempt); }
            else { resolve({ error: lastReason }); }
          });
      }
      tryFetch();
    });
    kiwiWorkerAssetCache[url] = promise;
    // Failed fetches are evicted (see the runtime cache): Retry can
    // succeed after a transient error without a page reload.
    promise.then(function (res) { if (res && res.error) delete kiwiWorkerAssetCache[url]; });
    return promise;
  }
  function solveWithWorker(data, onProgress, container, deadline, W) {
    var worker = null;
    var blobUrl = null;
    // Blob-URL cleanup: the URL is revoked exactly once on every terminal
    // path (done, failed, mismatch, worker error, deadline, termination);
    // terminate() kills the worker, revoking only releases the URL.
    function teardown() {
      if (blobUrl) {
        URL.revokeObjectURL(blobUrl);
        blobUrl = null;
      }
    }
    // A cancelled generation terminates the worker outright — revoking
    // the blob URL alone would not stop it. The handle is ONE stable
    // closure over the mutable `worker` slot: the caller holds it from
    // the first synchronous tick, so a call before the async
    // construction settles is a safe no-op and a later one terminates
    // whichever worker currently occupies the slot.
    var terminateHandle = function () {
      if (worker) { try { worker.terminate(); } catch (e) {} }
      teardown();
    };
    // The normalized algorithm of the solve message: argon2id/rsw pass
    // through, and a SHA-256 challenge (the default when the field is
    // absent) rides as "sha256" so the worker dispatches its wasm-first
    // solveSha rather than the memory-hard solver. The message shape is
    // unchanged: every solve carries the full field set, and only an
    // rsw solve adds the nonce and modulus.
    var algorithm = data.algorithm === "argon2id" ? "argon2id" : (data.algorithm === "rsw" ? "rsw" : "sha256");
    // The one configuration reader: the widget element wins over the
    // container here too (this worker path used to read the container
    // only, contradicting kiwiConfigValue).
    var workerSrc = kiwiRiskConfigValue(W, container, "data-kiwi-worker-src");
    var workerIntegrity = kiwiRiskConfigValue(W, container, "data-kiwi-worker-integrity");
    var runtimeSrc = kiwiRiskConfigValue(W, container, "data-kiwi-runtime-src");
    var runtimeIntegrity = kiwiRiskConfigValue(W, container, "data-kiwi-runtime-integrity");
    // An unverified runtime is trusted only on the page's own origin: a
    // runtime URL without a digest that resolves cross-origin (or does
    // not parse) is treated as unconfigured, so it is never fetched and
    // never embedded — the existing refusal/degraded path runs instead.
    if (runtimeSrc && !runtimeIntegrity) {
      var resolvedRuntime = null;
      try { resolvedRuntime = new URL(runtimeSrc, window.location.href); } catch (e) {}
      if (!resolvedRuntime || resolvedRuntime.origin !== window.location.origin) runtimeSrc = null;
    }
    // Files-mode worker asset: a versioned worker URL WITH its integrity
    // digest is the theme-emitted lazy worker asset (fetched and
    // preflight-verified below). A worker URL WITHOUT the integrity
    // attribute keeps the legacy explicit static-worker path — surfaced
    // once per page as the unverified state it is.
    var lazyWorkerAsset = !!(workerSrc && workerIntegrity);
    if (workerSrc && !workerIntegrity) kiwiWarnIntegrityOff();
    // The glue source: the inline script element (inline mode), the
    // compat loader's fetched glue (/api.js), or the lazy runtime fetch
    // of files mode.
    var glue = workerSrc ? null : (kiwiBridge.core.findGlueSource() || kiwiBridge.compatGlue);
    // The runtime URL handed to the worker through the { type: "glue" }
    // handshake, so the worker never probes an unversioned URL on its own.
    var glueRuntimeSrc = null;
    if (lazyWorkerAsset) {
      glueRuntimeSrc = runtimeSrc;
    } else if (workerSrc) {
      try {
        glueRuntimeSrc = new URL("kiwicaptcha-wasm.js", new URL(workerSrc, window.location.href).href).href;
      } catch (e) {}
    }
    var glueReady;
    if (workerSrc) {
      // URL-constructed worker: the worker importScripts the runtime URL
      // the driver supplies. Files mode still fetches + preflight-verifies
      // the runtime glue first: the immutable content-addressed URL then
      // serves identical bytes to the worker from the HTTP cache (one
      // download per page). The legacy static-worker path needs no
      // driver-side fetch, but the URL is still supplied explicitly.
      glueReady = lazyWorkerAsset && runtimeSrc
        ? kiwiFetchRuntimeGlue(runtimeSrc, runtimeIntegrity)
        : Promise.resolve({ src: null });
    } else {
      glueReady = glue
        ? Promise.resolve({ src: glue })
        : (runtimeSrc ? kiwiFetchRuntimeGlue(runtimeSrc, runtimeIntegrity) : Promise.resolve({ src: null }));
    }
    var workerReady = lazyWorkerAsset
      ? kiwiFetchWorkerAsset(workerSrc, workerIntegrity)
      : Promise.resolve({ src: null });
    var promise = Promise.all([glueReady, workerReady]).then(function (both) {
      var glueResult = both[0];
      var workerResult = both[1];
      if (glueResult && glueResult.error) {
        return { unavailable: true, reason: glueResult.error };
      }
      if (workerResult && workerResult.error) {
        return { unavailable: true, reason: workerResult.error };
      }
      var resolvedGlue = glueResult ? glueResult.src : null;
      return new Promise(function(resolve) {
        if (typeof Worker === "undefined") { resolve({ unavailable: true, reason: "no-worker-support" }); return; }
        try {
          if (workerSrc) {
            // Files mode: a same-ORIGIN Worker constructed from the
            // content-addressed URL of the fetched + preflight-verified
            // asset. The preflight hashes the EXACT fetched bytes and
            // (when integrity is present) requires the URL's embedded
            // sha256 to equal that digest, so the immutable URL the
            // browser's worker-script fetcher loads is pinned to the
            // verified bytes. That is a main-thread preflight, not an
            // in-worker re-verification; no Blob is created, so files
            // mode needs worker-src 'self' (or the content-addressed
            // source).
            worker = new Worker(workerSrc);
          } else {
            // Inline mode: the glue's embedded workerSource plus the
            // inline glue source, byte-identical.
            var workerSource = kiwiBridge.core.embeddedWorkerSource();
            if (!workerSource) { resolve({ unavailable: true, reason: "worker-source-unavailable" }); return; }
            var blobSrc = (resolvedGlue ? "var window = self;" + resolvedGlue + "\n" : "") + workerSource;
            blobUrl = URL.createObjectURL(new Blob([blobSrc], { type: "application/javascript" }));
            worker = new Worker(blobUrl);
          }
        } catch (e) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
        if (!worker) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
        window.__kiwiWorkerUsed = true;
        var workerStart = performance.now();
        // The progress denominator: an rsw solve reports squarings done,
        // every other solve reports hashes against 2^target_bits.
        var expectedUnits = algorithm === "rsw"
          ? (data.t || 1)
          : Math.pow(2, data.targetBits);
        var settled = false;
        // The solve deadline (challenge expiry − margin): a solve that
        // would outlive the challenge is wasted work, so the worker is
        // terminated at the deadline; the driver then re-acquires.
        var deadlineTimer = null;
        if (deadline && deadline > performance.now()) {
          deadlineTimer = setTimeout(function () {
            if (settled) return;
            settled = true;
            clearTimeout(deadlineTimer);
            try { worker.terminate(); } catch (e) {}
            teardown();
            resolve({ deadline: true });
          }, deadline - performance.now());
        }
        // The worker is created by this driver, so no cross-origin
        // postMessage target exists; admission rate limiting is server
        // side. The shape guard is defense in depth: any message that is
        // not a versioned progress/done/failed message is ignored.
        worker.onmessage = function(ev) {
          var msg = ev.data;
          // Arrays and non-objects are ignored: a schema-confused frame
          // never settles or steers the solve.
          if (!msg || typeof msg !== "object" || Array.isArray(msg) || msg.v !== 1) return;
          // One settle per solve: after the first terminal frame (done,
          // failed, mismatch, deadline) every later message — a
          // duplicate done, a stale progress or a foreign reply — is
          // ignored.
          if (settled) return;
          if (msg.type === "ready") {
            // Startup handshake: a stale cached worker must report the
            // same solver protocol id; otherwise it is refused and never
            // contributes a solution.
            if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_PROTOCOL_ID) {
              if (!settled) {
                console.error("KiwiCaptcha worker protocol mismatch: ready buildId", msg.buildId);
                settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true });
              }
            }
            return;
          }
          if (msg.type === "progress") {
            if (msg.reqId !== solveReqId) return;
            if (typeof msg.counter !== "number" || !isFinite(msg.counter)) return;
            onProgress(Math.min(95, (msg.counter * 100) / expectedUnits));
          } else if (msg.type === "done") {
            // Correlation is mandatory for a done: an uncorrelated (or
            // foreign) done must never settle this solve.
            if (msg.reqId !== solveReqId) return;
            if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_PROTOCOL_ID) {
              if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true }); }
              return;
            }
            var isRsw = algorithm === "rsw";
            // An rsw solve reports the final proof value, never a counter.
            if (isRsw) {
              if (typeof msg.proof !== "string" || !/^[0-9a-f]{512}$/.test(msg.proof)) {
                if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true }); }
                return;
              }
            } else if (typeof msg.counter !== "number" || !Number.isFinite(msg.counter)
              || !Number.isInteger(msg.counter) || msg.counter < 0 || msg.counter >= MAX_SHA_HASHES) {
              // A settle-shaped done must also be a real solution shape:
              // the counter is an integer inside the solver's own search
              // range [0, MAX_SHA_HASHES). Nonsense counters are ignored
              // (the server would refuse them anyway), so a false client
              // success is never painted from a malformed frame.
              return;
            }
            settled = true;
            clearTimeout(deadlineTimer);
            worker.terminate();
            teardown();
            resolve(isRsw
              ? { proof: msg.proof, duration: Math.round(performance.now() - workerStart) }
              : { counter: msg.counter, duration: Math.round(performance.now() - workerStart) });
          } else if (msg.type === "failed") {
            // Pre-solve handshake failures carry no reqId; a solve-scoped
            // failure must be correlated to this request.
            if (msg.reqId !== undefined && msg.reqId !== solveReqId) return;
            if (typeof msg.reason !== "string") return;
            // protocol-mismatch (the wasm/worker generations differ) is
            // surfaced as the controlled solver-mismatch state, same UX as
            // a wrong ready-handshake id.
            if (msg.reason === "protocol-mismatch") {
              if (!settled) {
                console.error("KiwiCaptcha worker protocol mismatch: wasm/worker generation differ");
                settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true });
              }
              return;
            }
            settled = true;
            clearTimeout(deadlineTimer);
            worker.terminate();
            teardown();
            console.error("KiwiCaptcha worker failed:", msg.reason);
            resolve({ unavailable: true, reason: "worker-failed-" + msg.reason });
          }
        };
        worker.onerror = function(ev) {
          if (settled) return;
          settled = true;
          clearTimeout(deadlineTimer);
          worker.terminate();
          teardown();
          console.error("KiwiCaptcha worker error:", ev && ev.message, ev && ev.filename, ev && ev.lineno);
          resolve({ unavailable: true, reason: "worker-error" });
        };
        var prefixBytes = encoder.encode(data.prefix);
        var saltBytes = b64decode(data.salt);
        var isRsw = algorithm === "rsw";
        // The solve request id: the worker echoes it on every solve-scoped
        // reply and the listener accepts correlated replies only, so a
        // page script posting a crafted solve+done pair into the worker
        // can never settle this solve (the reply it provokes carries the
        // other request's id, or none at all). The id comes from the
        // correlation CSPRNG (128 random bits) and NEVER from the
        // presentation fallback: a defense against false settlement must
        // not silently become predictable. Missing crypto fails the
        // worker path closed into the controlled unavailable state (the
        // driver then solves in-page).
        var reqWords = kiwiCorrelationWords();
        if (reqWords === null) {
          if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ unavailable: true, reason: "no-csprng" }); }
          return;
        }
        var solveReqId = "q" + reqWords[0].toString(36) + reqWords[1].toString(36) + reqWords[2].toString(36) + reqWords[3].toString(36);
        try {
          // Hand the runtime URL to the worker BEFORE the solve: it
          // importScripts the URL, verifies the wasm protocol version and
          // only then solves; the solve message queues behind the glue
          // handshake. The worker only accepts a same-origin runtime URL.
          if (glueRuntimeSrc) {
            worker.postMessage({ v: 1, type: "glue", runtimeSrc: glueRuntimeSrc });
          }
          // The solve message carries the full field set; an rsw solve
          // adds the nonce and the base64 modulus (the rsw solver never
          // touches the wasm module, so a missing glue still solves).
          var solveMsg = {
            v: 1,
            type: "solve",
            reqId: solveReqId,
            algorithm: algorithm,
            prefix: data.prefix,
            prefixLen: prefixBytes.length,
            salt: data.salt,
            saltLen: saltBytes.length,
            targetBits: data.targetBits,
            mKib: data.mKib || 0,
            t: data.t || 1,
            p: data.p || 1,
            startCounter: 0,
            maxHashes: MAX_SHA_HASHES,
          };
          if (isRsw) {
            solveMsg.nonce = data.nonce;
            solveMsg.modulus = data.rsw_modulus;
          }
          worker.postMessage(solveMsg);
        } catch (e) {
          if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ unavailable: true, reason: "post-failed" }); }
        }
      });
    });
    return { promise: promise, terminate: terminateHandle };
  }

  // ── Server-issued decoy (honeypot) field ────────────────────────────
  // The server may name a decoy field (bounded [A-Za-z0-9_-]{1,64}; a
  // malformed name is ignored). The module renders ONE hidden, non-
  // interactive, autofill-safe input of that name in the token's host;
  // the rendering strategy (0-5) is chosen per challenge from the
  // client-side CSPRNG (or the optional non-authenticated fixture hint)
  // INDEPENDENTLY of the name, so a bot cannot derive the surface from
  // the served name. The strategy choice is presentation-only: the
  // decoy evidence, proof, state machine and risk controls are
  // independent of it. The module NEVER auto-fills the decoy; a human
  // never types into it.
  var KIWI_DECOY_VARIANT_COUNT = 6;
  var KIWI_DECOY_WRAP_CLASSES = ["kiwi-form-aux", "kiwi-form-aux-alt", "kiwi-field-aux", "kiwi-aux-group"];
  // Client-side CSPRNG word; the engine fallback is presentation-only
  // (the strategy and wrapper class are never security boundaries).
  function kiwiCspUint32() {
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      var buf = new Uint32Array(1);
      window.crypto.getRandomValues(buf);
      return buf[0] >>> 0;
    }
    return Math.floor(Math.random() * 4294967296) >>> 0;
  }
  // The correlation CSPRNG: the solve request id gates which worker
  // replies may settle a solve, so it must NEVER degrade to the
  // presentation fallback. Unlike kiwiCspUint32 it has no non-crypto
  // path: missing getRandomValues returns null and the caller fails the
  // worker path closed into the controlled unavailable state. 128 random
  // bits make a guessed/colliding request id infeasible.
  function kiwiCorrelationWords() {
    if (!window.crypto || typeof window.crypto.getRandomValues !== "function") return null;
    var buf = new Uint32Array(4);
    window.crypto.getRandomValues(buf);
    return buf;
  }
  function kiwiDecoyVariantFor(data) {
    var hint = data && typeof data.strategy === "number" ? data.strategy : null;
    if (hint !== null && hint >= 0 && hint < KIWI_DECOY_VARIANT_COUNT && hint === Math.floor(hint)) {
      return hint;
    }
    return kiwiCspUint32() % KIWI_DECOY_VARIANT_COUNT;
  }
  // The owned decoy input of a widget's private decoy state, or null. The
  // owned set is authoritative: a same-named application field is never
  // found, read or removed.
  function kiwiOwnedDecoyInput(state) {
    var nodes = state.nodes || [];
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!node || !node.parentNode) continue;
      if (node.tagName === "INPUT") return node;
      var inner = node.querySelector ? node.querySelector("input") : null;
      if (inner && inner.parentNode) return inner;
    }
    return null;
  }
  // Remove ONLY the nodes in the widget's private owned set — never a
  // node identified by name match.
  function kiwiRemoveOwnedDecoys(state) {
    var nodes = state.nodes || [];
    state.nodes = [];
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!node || !node.parentNode) continue;
      try { node.parentNode.removeChild(node); } catch (e) {}
    }
  }
  function kiwiInsertDecoyInput(host, decoyName, variant, state, tokenEl) {
    var input = document.createElement("input");
    input.type = "text";
    input.name = decoyName;
    input.value = "";
    input.setAttribute("tabindex", "-1");
    input.setAttribute("aria-hidden", "true");
    var before = variant === 2 || variant === 4;
    var el = input;
    if (variant === 1 || variant === 4) {
      var wrap = document.createElement("span");
      if (!state.className) state.className = KIWI_DECOY_WRAP_CLASSES[kiwiCspUint32() % KIWI_DECOY_WRAP_CLASSES.length];
      wrap.className = state.className;
      wrap.appendChild(input);
      el = wrap;
    }
    host.insertBefore(el, before ? tokenEl : tokenEl.nextSibling);
    state.nodes.push(el);
    if (variant === 0 || variant === 1 || variant === 5) {
      input.style.display = "none";
      input.setAttribute("autocomplete", "off");
    } else if (variant === 2 || variant === 4) {
      input.setAttribute("hidden", "");
      // Inline display:none beats a site stylesheet that would otherwise
      // render hidden-attribute inputs (input { display: block }).
      input.style.display = "none";
      input.setAttribute("autocomplete", "off");
    } else {
      // Never new-password: that invites password-manager and browser
      // autofill to populate the decoy on legitimate users.
      input.setAttribute("autocomplete", "off");
      input.setAttribute("aria-label", "off-screen field");
      input.style.position = "absolute";
      input.style.left = "-9999px";
      input.style.width = "1px";
      input.style.height = "1px";
      input.style.margin = "-1px";
      input.style.padding = "0";
      input.style.border = "0";
      input.style.overflow = "hidden";
      input.style.whiteSpace = "nowrap";
      input.style.clip = "rect(0 0 0 0)";
      input.style.clipPath = "inset(50%)";
    }
  }
  // Render the server-issued decoy into the widget's form host. The
  // decoy state is the widget record's PRIVATE state (it survives re-
  // inits: an expiry-triggered re-solve still sees a filled decoy as
  // evidence). A re-issued challenge carries a NEW name: nodes owned
  // under the earlier name are removed so the form never accumulates
  // stale honeypot fields; a same-name reissue never duplicates.
  function kiwiRenderDecoy(data, decoyState, tokenEl) {
    var decoyName = data && typeof data.decoy_field === "string" ? data.decoy_field : null;
    if (decoyName === null || !/^[A-Za-z0-9_-]{1,64}$/.test(decoyName)) return;
    if (!tokenEl) return;
    var host = tokenEl.parentNode;
    if (!host) return;
    var previous = decoyState.name;
    if (previous && previous !== decoyName) {
      kiwiRemoveOwnedDecoys(decoyState);
      decoyState.className = null;
    }
    decoyState.name = decoyName;
    if (kiwiOwnedDecoyInput(decoyState)) {
      decoyState.deferred = false;
      return;
    }
    var variant = kiwiDecoyVariantFor(data);
    decoyState.variant = variant;
    if (variant === 5) {
      // The deferred strategy records the name now and creates the input
      // when the first solve completes (kiwiFlushDecoy).
      decoyState.deferred = true;
      return;
    }
    decoyState.deferred = false;
    kiwiInsertDecoyInput(host, decoyName, variant, decoyState, tokenEl);
  }
  // The deferred strategy (variant 5) creates its input only once the
  // first solve completes: called by the core right after the token is
  // written.
  function kiwiFlushDecoy(decoyState, tokenEl) {
    if (!tokenEl || !decoyState.deferred) return;
    decoyState.deferred = false;
    var decoyName = decoyState.name;
    if (!decoyName) return;
    var host = tokenEl.parentNode;
    if (!host) return;
    kiwiInsertDecoyInput(host, decoyName, 5, decoyState, tokenEl);
  }
  // The filled-decoy honeypot markers for the NEXT challenge request:
  // when the widget's own decoy input is still in the form and FILLED,
  // the name + a bounded value ride the request as honeypot evidence —
  // never a gate. The value is truncated to the server's 256-byte bound
  // by the eager core's bridge.core.boundBytes; an empty decoy
  // contributes nothing. The read is ownership-based, never a name query.
  function kiwiReadHoneypot(decoyState, tokenEl) {
    if (!decoyState || !decoyState.name || !tokenEl) return null;
    var decoyInput = kiwiOwnedDecoyInput(decoyState);
    if (decoyInput && decoyInput.parentNode && typeof decoyInput.value === "string" && decoyInput.value !== "") {
      var truncate = (kiwiBridge && kiwiBridge.core && typeof kiwiBridge.core.boundBytes === "function")
        ? kiwiBridge.core.boundBytes
        : function (s) { return s; };
      return { name: decoyState.name, value: truncate(decoyInput.value, 256) };
    }
    return null;
  }

  // Register on the internal core bridge the moment this module executes
  // (the core injects the SRI-pinned script only when a trigger fired);
  // a module script that somehow ran before the core is inert.
  var kiwiBridge = (typeof window !== "undefined" && window.__kiwiCaptchaCore) || null;
  if (kiwiBridge && typeof kiwiBridge.register === "function") {
    kiwiBridge.register("risk", {
      readHoneypot: kiwiReadHoneypot,
      renderDecoy: kiwiRenderDecoy,
      flushDecoy: kiwiFlushDecoy,
      runExecution: kiwiRunExecution,
      solveWorker: solveWithWorker
    });
  }
})();
