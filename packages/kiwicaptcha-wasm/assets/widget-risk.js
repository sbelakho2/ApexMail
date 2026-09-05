(function () {
  var encoder = new TextEncoder();
  // Solver protocol/ABI generation label, identical to the eager core's
  // literal (the spec asserts the copies agree) and verified by the worker
  // in its ready/done handshake; a stale cached worker is refused. This
  // pins driver+worker+wasm protocol compatibility only, never artifact
  // identity (that is the release tag + SHA256SUMS + SRI chain).
  var KIWI_SOLVER_PROTOCOL_ID = "2026-09-r1";
  // Bounded search cap, identical to the eager core's constant; the
  // worker enforces it there, the solve message carries it here.
  var MAX_SHA_HASHES = 5000000;
  function b64decode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return Uint8Array.from(atob(str), function(c) { return c.charCodeAt(0); });
  }

  // ── The lazy risk tier ──────────────────────────────────────────────
  // Loaded ONLY when an armed response or configuration needs it: an
  // argon2id/rsw widget (adaptive solve tier), a server decoy field /
  // strategy hint, or an execution_program. Files mode injects this
  // module as a same-origin SRI-pinned script (native SRI fails closed);
  // inline mode embeds it. The module registers on the internal core
  // bridge and stays stateless: widget state is passed in per call.
  // Failure semantics: decoy/honeypot evidence is probabilistic, never a
  // gate (an unloadable module degrades to the absent default with a
  // console.warn); solve tiers fail closed into the controlled
  // kiwi:worker-unavailable / kiwi:execution-unavailable states — never
  // a silent success, never a weaker-profile fallback. The coarse
  // client-context descriptor moved into the eager core; this module
  // still reads it and bridge.core.boundBytes for decoy evidence.
  var kiwiExecutionRunCounter = 0;
  var KIWI_EXECUTION_TIMEOUT_MS = 10000;
  // Run one execution program in a fresh sandboxed ephemeral iframe and
  // resolve with the 64-hex digest, or reject with a reason (fail
  // closed). The iframe is removed after the run.
  function kiwiRunExecution(program, nonce, container, W) {
    return new Promise(function (resolve, reject) {
      var executionSrc = (container.getAttribute ? container.getAttribute("data-kiwi-execution-src") : null)
        || (W.getAttribute ? W.getAttribute("data-kiwi-execution-src") : null);
      var executionIntegrity = (container.getAttribute ? container.getAttribute("data-kiwi-execution-integrity") : null)
        || (W.getAttribute ? W.getAttribute("data-kiwi-execution-integrity") : null);
      if (!executionSrc || !executionIntegrity) {
        reject("execution-asset-unconfigured");
        return;
      }
      var iframe = document.createElement("iframe");
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

  // ── The same-origin Argon2id/rsw solve tier ─────────────────────────
  // The memory-hard and sequential time-lock solvers ALWAYS run off the
  // main thread; a missing/failed worker enters the controlled
  // kiwi:worker-unavailable state — no main-thread Argon2 hash and no
  // weaker-profile retry, ever. All postMessage traffic here is
  // worker-internal; forged page traffic is ignored (the spec asserts
  // forged payloads never mint a token). Inline mode builds the Blob
  // worker from the glue's embedded workerSource (zero requests);
  // files mode constructs a SAME-ORIGIN Worker from the fetched,
  // preflight-verified versioned asset (no Blob URL, so worker-src
  // 'self' suffices, never blob:); the legacy explicit data-kiwi-worker-
  // src URL keeps its direct-construction path. The worker never probes
  // an unversioned runtime: the driver always supplies the runtime URL
  // through the { type: "glue" } handshake below.
  var kiwiActiveBlobUrl = null; // shared so reset/unavailable paths can revoke
  function kiwiRevokeActiveBlobUrl() {
    if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
  }
  // ── Files-mode lazy asset loading (runtime + worker) ────────────────
  // In files mode the runtime glue and worker assets are fetched ONLY
  // when a memory-hard challenge arrives; both fetches are bounded (two
  // retries), deduplicated per URL across the page, and preflight-
  // verified against the page-issued sha256 digests BEFORE the bytes are
  // used. The verification FAILS CLOSED: when a digest is demanded but
  // the page cannot compute it (no crypto.subtle.digest) the fetch is
  // refused with integrity-unverifiable — an unverifiable asset never
  // runs, and a mismatch never reaches the browser APIs.
  var kiwiRuntimeGlueCache = {};
  var kiwiWorkerAssetCache = {};
  function kiwiVerifyIntegrity(src, integrity) {
    if (!integrity) return Promise.resolve({ ok: true });
    var expected = integrity.indexOf("sha256-") === 0 ? integrity.slice(7) : null;
    if (!expected) return Promise.resolve({ ok: false, reason: "integrity-malformed" });
    if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.digest) {
      return Promise.resolve({ ok: false, reason: "integrity-unverifiable" });
    }
    return crypto.subtle.digest("SHA-256", encoder.encode(src)).then(function (buf) {
      var bytes = new Uint8Array(buf);
      var bin = "";
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin) === expected ? { ok: true } : { ok: false, reason: "integrity-mismatch" };
    }).catch(function () { return { ok: false, reason: "integrity-unverifiable" }; });
  }
  function kiwiFetchRuntimeGlue(url, integrity) {
    if (kiwiRuntimeGlueCache[url]) return kiwiRuntimeGlueCache[url];
    var promise = new Promise(function (resolve) {
      var attempt = 0;
      var lastReason = "runtime-unavailable";
      function tryFetch() {
        fetch(url, { cache: "force-cache", credentials: "same-origin" })
          .then(function (r) { if (!r.ok) { lastReason = "runtime-fetch-" + r.status; throw new Error("KiwiCaptcha runtime fetch failed"); } return r.text(); })
          .then(function (src) {
            if (src.indexOf("var KIWI_WASM_B64") === -1 || src.indexOf("__kiwiCaptchaWasm") === -1) {
              lastReason = "runtime-malformed";
              throw new Error("KiwiCaptcha runtime asset malformed");
            }
            return kiwiVerifyIntegrity(src, integrity).then(function (res) {
              if (!res.ok) { lastReason = res.reason; throw new Error("KiwiCaptcha runtime integrity failure"); }
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
    return promise;
  }
  function kiwiFetchWorkerAsset(url, integrity) {
    if (kiwiWorkerAssetCache[url]) return kiwiWorkerAssetCache[url];
    var promise = new Promise(function (resolve) {
      var attempt = 0;
      var lastReason = "worker-unavailable";
      function tryFetch() {
        fetch(url, { cache: "force-cache", credentials: "same-origin" })
          .then(function (r) { if (!r.ok) { lastReason = "worker-fetch-" + r.status; throw new Error("KiwiCaptcha worker asset fetch failed"); } return r.text(); })
          .then(function (src) {
            if (src.indexOf("KiwiCaptcha worker solver") === -1) {
              lastReason = "worker-malformed";
              throw new Error("KiwiCaptcha worker asset malformed");
            }
            return kiwiVerifyIntegrity(src, integrity).then(function (res) {
              if (!res.ok) { lastReason = res.reason; throw new Error("KiwiCaptcha worker integrity failure"); }
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
    return promise;
  }
  function solveWithWorker(data, onProgress, container, deadline) {
    var terminateHandle = function () {};
    var workerSrc = container.getAttribute("data-kiwi-worker-src");
    var workerIntegrity = container.getAttribute("data-kiwi-worker-integrity");
    var runtimeSrc = container.getAttribute("data-kiwi-runtime-src");
    var runtimeIntegrity = container.getAttribute("data-kiwi-runtime-integrity");
    // Files-mode worker asset: a versioned worker URL WITH its integrity
    // digest is the theme-emitted lazy worker asset (fetched and
    // preflight-verified below). A worker URL WITHOUT the integrity
    // attribute keeps the legacy explicit static-worker path.
    var lazyWorkerAsset = !!(workerSrc && workerIntegrity);
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
        var worker = null;
        var blobUrl = null;
        try {
          if (workerSrc) {
            // Files mode: a SAME-ORIGIN Worker constructed from the
            // content-addressed URL of the fetched + preflight-verified
            // asset. The Worker constructor loads the same immutable URL
            // through the browser's worker-script fetcher — it can only
            // ever serve the exact verified bytes (the hash is in the
            // URL), so the running worker IS the verified source; no
            // Blob is created, so files mode needs worker-src 'self'.
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
        kiwiRevokeActiveBlobUrl();
        kiwiActiveBlobUrl = blobUrl;
        // A cancelled generation terminates the worker outright — revoking
        // the blob URL alone would not stop it.
        terminateHandle = function () {
          try { worker.terminate(); } catch (e) {}
          teardown();
        };
        window.__kiwiWorkerUsed = true;
        var workerStart = performance.now();
        // The progress denominator: an rsw solve reports squarings done,
        // every other solve reports hashes against 2^target_bits.
        var expectedUnits = (data.algorithm || "sha256") === "rsw"
          ? (data.t || 1)
          : Math.pow(2, data.targetBits);
        var settled = false;
        // Blob-URL cleanup: the URL is revoked exactly once on every
        // terminal path (done, failed, mismatch, worker error, deadline);
        // terminate() kills the worker, revoking only releases the URL.
        function teardown() {
          if (blobUrl) {
            URL.revokeObjectURL(blobUrl);
            if (kiwiActiveBlobUrl === blobUrl) kiwiActiveBlobUrl = null;
            blobUrl = null;
          }
        }
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
          if (!msg || typeof msg !== "object" || msg.v !== 1) return;
          if (msg.type === "ready") {
            // Startup handshake: a stale cached worker must report the
            // SAME solver protocol id; otherwise it is refused and never
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
            if (typeof msg.counter !== "number" || !isFinite(msg.counter)) return;
            onProgress(Math.min(95, (msg.counter * 100) / expectedUnits));
          } else if (msg.type === "done") {
            if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_PROTOCOL_ID) {
              if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true }); }
              return;
            }
            var isRsw = (data.algorithm || "sha256") === "rsw";
            // An rsw solve reports the final proof value, never a counter.
            if (isRsw) {
              if (typeof msg.proof !== "string" || !/^[0-9a-f]{512}$/.test(msg.proof)) {
                if (!settled) { settled = true; clearTimeout(deadlineTimer); worker.terminate(); teardown(); resolve({ mismatch: true }); }
                return;
              }
            } else if (typeof msg.counter !== "number" || !isFinite(msg.counter)) {
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
        var isRsw = (data.algorithm || "sha256") === "rsw";
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
            algorithm: isRsw ? "rsw" : "argon2id",
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
      input.setAttribute("autocomplete", "off");
    } else {
      input.setAttribute("autocomplete", "new-password");
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
      solveWorker: solveWithWorker,
      revokeWorkerUrl: kiwiRevokeActiveBlobUrl
    });
  }
})();
