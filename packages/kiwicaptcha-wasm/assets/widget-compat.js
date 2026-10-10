(function () {
  // ── widget-compat.js: the incumbent compatibility loader ───────────
  // Runs only on the compat route (delivered inside /api.js after the
  // /*KIWI_COMPAT_SPLIT*/ marker): renders the incumbent containers,
  // installs the provider global, mirrors the provider response field.
  var K = (typeof window !== "undefined" && window.__kiwiCaptchaCore) || null;
  if (!K || !K.core) return;
  var core = K.core;

  // Loader parser (URLSearchParams): compat, render, onload, hl.
  function parseCompatLoader(scriptUrl) {
    var out = { provider: null, renderMode: "auto", onloadName: null, language: null };
    if (!scriptUrl) return out;
    var url;
    try {
      url = new URL(scriptUrl, document.baseURI);
    } catch (e) {
      return out;
    }
    var compatParam = url.searchParams.get("compat");
    if (compatParam === "recaptcha" || compatParam === "hcaptcha" || compatParam === "turnstile") {
      out.provider = compatParam;
    }
    if (url.searchParams.get("render") === "explicit") out.renderMode = "explicit";
    var onloadParam = url.searchParams.get("onload");
    if (typeof onloadParam === "string" && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(onloadParam)) {
      out.onloadName = onloadParam;
    }
    var hl = url.searchParams.get("hl");
    if (typeof hl === "string" && hl !== "") out.language = core.normalizeLang(hl) || null;
    return out;
  }
  var compatScriptUrl = null;
  var compat = null;
  var compatRenderMode = "auto";
  var compatOnloadName = null;
  try {
    var compatScript = document.currentScript;
    if (!compatScript) {
      var compatScripts = document.getElementsByTagName("script");
      compatScript = compatScripts[compatScripts.length - 1];
    }
    compatScriptUrl = compatScript && compatScript.src ? compatScript.src : null;
    var compatLoader = parseCompatLoader(compatScriptUrl);
    compat = compatLoader.provider;
    compatRenderMode = compatLoader.renderMode;
    compatOnloadName = compatLoader.onloadName;
  } catch (e) {}
  if (!compat || !compatScriptUrl) return;
  // Route/asset bases derive from the loader's own script URL.
  var compatAssetBase = compatScriptUrl.split("?")[0].replace(/[^/]*$/, "");
  var compatRouteBase = "/";
  try { compatRouteBase = new URL(compatScriptUrl, document.baseURI).pathname.replace(/[^/]*$/, ""); } catch (e) {}
  var compatEndpointDefault = compatRouteBase + "challenge";
  // The incumbent defaults an omitted id to the first created widget.
  var kiwiCompatFirstId = null;
  // Numeric Google ids (grecaptcha.reset(0)) map to creation order.
  var kiwiCompatOrderedIds = [];
  // Rebuild the worker prelude from the glue's executed constants
  // (K.compatGlue); the b64 constant's assembly digest fails closed.
  var kiwiCompatGlue = null;
  var kiwiCompatGlueReady = null;
  kiwiCompatGlueReady = Promise.resolve().then(function () {
    var W = typeof window !== "undefined" ? window.__kiwiCaptchaWasm : null;
    if (!W || typeof W.wasmB64 !== "string" || typeof W.glueBoot !== "string") return;
    kiwiCompatGlue = "var KIWI_WASM_B64=" + JSON.stringify(W.wasmB64) + ";\n" + W.glueBoot + "\n";
    if (K) K.compatGlue = kiwiCompatGlue;
    var stamp = typeof W.wasmB64Sha256 === "string" && W.wasmB64Sha256.indexOf("sha256-") === 0
      ? W.wasmB64Sha256.slice(7) : null;
    if (!stamp || !window.crypto || !window.crypto.subtle || !window.crypto.subtle.digest) return;
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(W.wasmB64)).then(function (buf) {
      var bytes = new Uint8Array(buf);
      var bin = "";
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      if (btoa(bin) !== stamp) {
        console.error("KiwiCaptcha: compat worker glue digest mismatch; dropping the worker runtime");
        kiwiCompatGlue = null;
        if (K) K.compatGlue = null;
      }
    }).catch(function () {});
  });

  var COMPAT_FIELD = { recaptcha: "g-recaptcha-response", hcaptcha: "h-captcha-response", turnstile: "cf-turnstile-response" }[compat];
  var COMPAT_SELECTOR = { recaptcha: ".g-recaptcha", hcaptcha: ".h-captcha", turnstile: ".cf-turnstile" }[compat];
  var COMPAT_SVG = '<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" stroke-width="6.6" stroke-linecap="round" stroke-linejoin="round" fill="none"><path d="M32 42 C32 35 43 35 43 42 C43 51 29 54 23 46 C16 36 25 28 35 29 C47 29 54 38 53 46 C52 56 43 60 31 59 C17 58 9 51 10 41 C10 33 16 28 21 28"/><path d="M22 25 V16 A10 10 0 0 1 42 16 V25"/></g></svg>';
  function compatInjectCss() {
    if (!compatScriptUrl || document.querySelector('link[data-kiwi-css]')) return;
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.setAttribute("data-kiwi-css", "");
    var base = compatAssetBase;
    link.href = base + "widget.css";
    document.head.appendChild(link);
  }
  // The loader's locales descriptor; the core lazily fetches a
  // non-default pack. English pays zero bytes.
  var compatLocales = (typeof window !== "undefined" && window.__kiwiCaptchaCompatLocales) || null;
  var compatLocalesAttrs = "";
  var compatLocalesSrc = "";
  // Only the bare hash/digest alphabet reaches the innerHTML sink.
  if (compatLocales && compatScriptUrl
    && /^[A-Za-z0-9+/=_-]+$/.test(String(compatLocales.hash))
    && /^[A-Za-z0-9+/=_-]+$/.test(String(compatLocales.sri))) {
    compatLocalesSrc = compatAssetBase + 'assets/locales.' + compatLocales.hash + '.js';
    compatLocalesAttrs = ' data-kiwi-locales-src="' + compatLocalesSrc + '"'
      + ' data-kiwi-locales-integrity="' + compatLocales.sri + '"';
  }
  // The loader's asset descriptor table: locales/telemetry/execution
  // entries resolve against the loader URL onto the render target as
  // data-kiwi-<kind>-src / -integrity (page attributes win).
  var compatDescriptorKinds = ["locales", "telemetry", "execution"];
  function compatApplyDescriptorAssets(renderTarget) {
    var table = (typeof window !== "undefined" && window.__kiwiCaptchaCompatAssets) || null;
    if (!table) return;
    for (var i = 0; i < compatDescriptorKinds.length; i++) {
      var kind = compatDescriptorKinds[i];
      var entry = table[kind];
      if (!entry || typeof entry.src !== "string" || !entry.src || typeof entry.sri !== "string") continue;
      if (!/^sha256-[A-Za-z0-9+/=_-]+$/.test(entry.sri)) continue;
      var srcAttr = "data-kiwi-" + kind + "-src";
      if (renderTarget.hasAttribute(srcAttr) || renderTarget.hasAttribute("data-kiwi-" + kind + "-integrity")) continue;
      renderTarget.setAttribute(srcAttr, compatAssetBase + entry.src);
      renderTarget.setAttribute("data-kiwi-" + kind + "-integrity", entry.sri);
    }
  }
  function compatMarkup() {
    return '<div class="kiwi-container"' + compatLocalesAttrs + '><input type="hidden" name="kiwi__token" data-kiwi-token value="">' +
      '<div class="kiwi-widget" data-kiwi-widget data-kiwi-started="1" data-state="idle" role="group" aria-label="KiwiCaptcha security check">' +
      '<div class="kiwi-icon-wrapper" aria-hidden="true">' + COMPAT_SVG + '</div>' +
      '<div class="kiwi-main"><div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>' +
      '<div class="kiwi-slots" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div><div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>' +
      '<div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected by KiwiCaptcha</p><span class="kiwi-timer" data-kiwi-timer></span></div></div>' +
      '<span class="kiwi-sr-only" data-kiwi-status role="status" aria-live="polite"></span></div></div>';
  }
  // Callback names resolve via own-property window lookups only: the
  // platform constructors and code-evaluation entries stay unreachable.
  var COMPAT_FORBIDDEN_CALLBACKS = {
    eval: true, Function: true, constructor: true, __proto__: true, prototype: true,
    setTimeout: true, setInterval: true, setImmediate: true, requestAnimationFrame: true,
  };
  function compatReadCallbacks(el, params) {
    var cb = function (name) {
      var v = (params && (params[name] !== undefined)) ? params[name]
        : (el.getAttribute("data-" + name.replace(/([A-Z])/g, "-$1").toLowerCase()) || "");
      if (typeof v === "function") return v;
      if (typeof v !== "string" || !v) return null;
      if (COMPAT_FORBIDDEN_CALLBACKS[v]) return null;
      if (!Object.prototype.hasOwnProperty.call(window, v)) return null;
      // A page accessor may throw; never strand the implicit loop.
      try {
        return typeof window[v] === "function" ? window[v] : null;
      } catch (e) {
        return null;
      }
    };
    return {
      callback: cb("callback"),
      expiredCallback: cb("expired-callback"),
      errorCallback: cb("error-callback")
    };
  }
  // Owned provider-control bindings: button and input controls render
  // into an adjacent holder, and this table backs resolve/remove and
  // the owned activation listener.
  var compatControlByElement = new WeakMap();
  // Null-prototype: the key is the widget render id (page-influenced).
  var compatControlById = Object.create(null);
  function compatIsControl(el) {
    return !!el && (el.tagName === "BUTTON" || el.tagName === "INPUT");
  }
  function compatIsInvisibleControl(el, params) {
    if (compatIsControl(el)) return true;
    if (el && el.getAttribute && el.getAttribute("data-size") === "invisible") return true;
    if (params && params.size === "invisible") return true;
    return false;
  }
  function compatForgetControl(entry) {
    if (!entry) return;
    if (entry.el) compatControlByElement.delete(entry.el);
    if (entry.id && compatControlById[entry.id] === entry) delete compatControlById[entry.id];
  }
  function compatBindActivation(el, id) {
    var entry = compatControlByElement.get(el);
    if (!entry || entry.id !== id || entry.activationHandler) return;
    entry.activationHandler = function (ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      // Fire-and-forget: failures surface via the error lifecycle only.
      Promise.resolve(core.execute(entry.id)).catch(function () {});
    };
    el.addEventListener("click", entry.activationHandler);
  }
  // render(target, params): the one render implementation, shared by the
  // provider surface, the implicit loop and the delegated paths. The
  // third argument marks an implicit (non-user) render, which must honor
  // the module-failure backoff.
  function compatRender(target, params, implicit) {
    // grecaptcha.render("id", ...) / render(selector, ...) resolve
    // through the same target resolver as the native API and return a
    // working widget id.
    var el = core.resolveTarget(target);
    if (!el || el.nodeType !== 1) return 0;
    if (!implicit && core.clearModuleBackoff) core.clearModuleBackoff();
    // Idempotent re-render, owned table first (a second solve on one
    // element would race the first).
    var boundEntry = compatControlByElement.get(el);
    if (boundEntry && core.record(boundEntry.id)) return boundEntry.id;
    if (el.dataset.kiwiInstance && core.record(el.dataset.kiwiInstance)) {
      return el.dataset.kiwiInstance;
    }
    var existingWidget = el.querySelector ? el.querySelector("[data-kiwi-widget]") : null;
    if (existingWidget && existingWidget.dataset.kiwiInstance && core.record(existingWidget.dataset.kiwiInstance)) {
      return existingWidget.dataset.kiwiInstance;
    }
    var isControl = compatIsControl(el);
    var invisibleControl = compatIsInvisibleControl(el, params);
    var renderTarget = el;
    var holder = null;
    if (isControl) {
      var priorEntry = compatControlByElement.get(el);
      if (priorEntry && priorEntry.holder && priorEntry.holder.parentNode) {
        holder = priorEntry.holder;
      } else {
        holder = document.createElement("div");
        holder.className = "kiwi-compat-holder";
        holder.setAttribute("data-kiwi-compat-holder", "");
        if (el.parentNode) el.parentNode.insertBefore(holder, el.nextSibling);
      }
      renderTarget = holder;
      if (!renderTarget.querySelector("[data-kiwi-widget]")) renderTarget.innerHTML = compatMarkup();
    } else if (!el.querySelector("[data-kiwi-widget]")) {
      el.innerHTML = compatMarkup();
    }
    // Copy supported config onto the exact renderTarget core.render reads.
    if (core.copySupportedConfiguration) core.copySupportedConfiguration(el, renderTarget);
    compatApplyDescriptorAssets(renderTarget);
    if (compatLocalesSrc && !renderTarget.hasAttribute("data-kiwi-locales-src")) {
      renderTarget.setAttribute("data-kiwi-locales-src", compatLocalesSrc);
      renderTarget.setAttribute("data-kiwi-locales-integrity", compatLocales.sri);
    }
    if (!renderTarget.hasAttribute("data-kiwi-endpoint")) {
      renderTarget.setAttribute("data-kiwi-endpoint", compatEndpointDefault);
    }
    var sitekey = (params && (params.sitekey || params["sitekey"])) || el.getAttribute("data-sitekey") || "";
    var cbs = compatReadCallbacks(el, params);
    var responseFieldName = (params && params["response-field"] === false)
      || el.getAttribute("data-response-field") === "false"
      ? false
      : ((params && typeof params["response-field-name"] === "string" && params["response-field-name"])
        || el.getAttribute("data-response-field-name") || COMPAT_FIELD);
    // The incumbent renders its response field at render time; only the
    // bounded field-name shape reaches this eager alias (other values go
    // to the driver's own validation), and a hostile page value setter
    // cannot break the render.
    if (typeof responseFieldName === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(responseFieldName)) {
      try {
        var tokenHost = (renderTarget.querySelector("[data-kiwi-token]") || {}).parentNode;
        // The field carries the incumbent's ID as well as the name, so
        // getElementById / $("#g-recaptcha-response") finds it; the
        // element stays Kiwi's hidden input (the documented compat
        // shape). hCaptcha also fills the reCAPTCHA field for drop-in
        // compatibility.
        var fieldNames = [responseFieldName];
        if (compat === "hcaptcha" && responseFieldName !== "g-recaptcha-response") {
          fieldNames.push("g-recaptcha-response");
        }
        for (var rf = 0; rf < fieldNames.length && tokenHost; rf++) {
          var fieldName = fieldNames[rf];
          var hostFields = tokenHost.querySelectorAll("input,textarea");
          var aliasExists = false;
          for (var hi = 0; hi < hostFields.length; hi++) {
            if (hostFields[hi].name === fieldName) { aliasExists = true; break; }
          }
          if (aliasExists) continue;
          var aliasField = document.createElement("input");
          aliasField.type = "hidden";
          aliasField.id = fieldName;
          aliasField.name = fieldName;
          aliasField.setAttribute("data-kiwi-response-alias", "");
          tokenHost.appendChild(aliasField);
        }
      } catch (e) {}
    }
    var id = (implicit && core.renderImplicit ? core.renderImplicit : core.render)(renderTarget, {
      scope: sitekey || "login",
      callback: cbs.callback,
      expiredCallback: cbs.expiredCallback,
      errorCallback: cbs.errorCallback,
      // Turnstile's response-field-name override; false keeps only the
      // internal token field.
      responseField: responseFieldName,
      // grecaptcha.render(el, {lang: "de"}) or data-kiwi-lang on the
      // incumbent container.
      lang: (params && typeof params.lang === "string" && params.lang)
        || el.getAttribute("data-kiwi-lang") || undefined,
      // Turnstile action/cData — forwarded to the challenge request at
      // issuance (server-owned binding).
      action: (params && typeof params.action === "string" && params.action)
        || el.getAttribute("data-action") || undefined,
      cData: (params && typeof params.cData === "string" && params.cData)
        || el.getAttribute("data-cdata") || undefined,
      // language: params/attribute, then the loader's own hl= fallback.
      language: (params && typeof params.language === "string" && params.language)
        || el.getAttribute("data-language")
        || (compatLoader && compatLoader.language) || undefined,
      // Explicit-execution mode: params/data-execution="execute", or an
      // invisible-class control (BUTTON/INPUT/data-size=invisible).
      execution: (params && typeof params.execution === "string")
        ? params.execution
        : (el.getAttribute("data-execution") === "execute"
          ? "execute"
          : (invisibleControl ? "execute" : undefined)),
      sitekey: sitekey || undefined
    });
    if (id) {
      // Activation ownership is separate from holder ownership: any
      // invisible-class element owns an activation record, while only a
      // BUTTON/INPUT control owns the adjacent holder.
      if (isControl || invisibleControl) {
        var entry = compatControlByElement.get(el);
        if (!entry) {
          entry = { el: el, id: null, holder: holder, activationHandler: null };
          compatControlByElement.set(el, entry);
        }
        entry.id = id;
        entry.holder = holder;
        compatControlById[id] = entry;
        compatBindActivation(el, id);
      }
      if (!kiwiCompatFirstId) kiwiCompatFirstId = id;
      if (kiwiCompatOrderedIds.indexOf(id) === -1) kiwiCompatOrderedIds.push(id);
    } else if (isControl) {
        if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
      compatForgetControl(compatControlByElement.get(el));
    }
    return id || 0;
  }
  // hCaptcha async execute() rejects with a stable error-code STRING:
  // transport failures are "network-error", solve failures
  // "challenge-error", everything else "internal-error".
  function kiwiHcaptchaErrorCode(err) {
    var name = err && err.name;
    if (name === "AbortError" || name === "TypeError") return "network-error";
    var lower = String((err && err.message) || "").toLowerCase();
    if (lower.indexOf("abort") !== -1 || lower.indexOf("fetch") !== -1 || lower.indexOf("network") !== -1 || lower.indexOf("load failed") !== -1 || lower.indexOf("challenge failed") !== -1) return "network-error";
    if (lower.indexOf("solve") !== -1 || lower.indexOf("downgrad") !== -1 || lower.indexOf("exhaust") !== -1 || lower.indexOf("challenge malformed") !== -1) return "challenge-error";
    return "internal-error";
  }
  function compatExecute(arg, opts) {
    // Implicit renders complete asynchronously (the glue bootstrap), so
    // execute() awaits kiwiCompatReady before resolving its target.
    var kiwiExecuteChain = (kiwiCompatReady || Promise.resolve()).then(function () {
    // hCaptcha async mode is decided before argument resolution: it
    // normalizes resolution failures to the incumbent error-code STRING.
    var hcaptchaAsync = compat === "hcaptcha" && opts && opts.async === true;
    var id = null;
    if (arg === undefined || arg === null) {
      // execute() with no argument targets the first created widget via
      // the shared resolver; hCaptcha async rejects a widget-less page
      // with the incumbent's "missing-captcha" STRING.
      id = compatResolveId(null);
      if (hcaptchaAsync && !id) return Promise.reject("missing-captcha");
      if (!id) return Promise.reject(new Error("kiwicaptcha: no widget has been rendered"));
    } else {
      // Resolution order: widget id, element id, container selector; an
      // unresolved string is a v3 sitekey only for reCAPTCHA.
      if (typeof arg === "string" && core.record(arg)) {
        id = arg;
      } else {
        var targetEl = null;
        if (typeof arg === "string") {
          try { targetEl = document.getElementById(arg); } catch (e) {}
          if (!targetEl) {
            try {
              var selectorMatches = document.querySelectorAll(arg);
              targetEl = selectorMatches.length ? selectorMatches[0] : null;
            } catch (e) {}
          }
        } else if (arg && arg.nodeType === 1) {
          targetEl = arg;
        }
        if (targetEl) id = compatResolveId(targetEl);
      }
      if (hcaptchaAsync && !id) {
        // The incumbent's "invalid-captcha-id" STRING.
        return Promise.reject("invalid-captcha-id");
      }
    }
    if (id) {
      var execPromise = core.execute(id);
      if (hcaptchaAsync) {
        // The async form resolves {response, key} and rejects with the
        // incumbent error-code STRING, never an Error object.
        return execPromise.then(function (token) {
          var rec = core.record(id);
          return { response: token, key: (rec && rec.responseKey) || "" };
        }).catch(function (err) { throw kiwiHcaptchaErrorCode(err); });
      }
      return execPromise;
    }
    if (compat !== "recaptcha") {
      return Promise.reject(new Error("kiwicaptcha: execute() target is not a rendered widget id, element, or container selector"));
    }
    // v3-style execute(sitekey, {action}) on a hidden widget; no
    // fabricated score is produced.
    var sitekey = typeof arg === "string" ? arg : "";
    var action = (opts && opts.action) || sitekey || "login";
    var holder = document.createElement("div");
    holder.style.display = "none";
    var inner = document.createElement("div");
    inner.className = "kiwi-container";
    inner.setAttribute("data-kiwi-scope", action);
    holder.appendChild(inner);
    document.body.appendChild(holder);
    // compatRender lands the compat endpoint/scope defaults on the
    // holder; the real sitekey and the action stay independent.
    var id2 = compatRender(inner, { sitekey: sitekey, action: action });
    if (!id2) {
      if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
      return Promise.reject(new Error("kiwicaptcha: hidden render failed"));
    }
    var p = core.execute(id2);
    // The hidden holder and widget are removed on both settlement arms.
    var holderDone = function () {
      if (id2 && core.record(id2)) core.remove(id2);
      if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
    };
    return Promise.resolve(p).then(function (tok) {
      holderDone();
      return tok;
    }, function (err) {
      holderDone();
      throw err;
    });
    });
    // The v2 contract is callback-style: pages ignore execute()'s return
    // value. Observe the rejection of the promise actually returned to
    // the page so such pages can never produce an unhandled rejection
    // (awaiting callers still receive the rejected promise; a tamed
    // promise merely has a handler attached).
    if (compat === "recaptcha") kiwiExecuteChain.catch(function () {});
    return kiwiExecuteChain;
  }
  function compatResolveId(idOrEl) {
    // Omitted id -> first render; number -> creation-order index; element
    // -> owned record then instance marker. A container without a live
    // widget resolves null (""/null/false), never throwing.
    if (idOrEl === undefined || idOrEl === null) return kiwiCompatFirstId;
    if (typeof idOrEl === "number" && Number.isInteger(idOrEl)) {
      var byIndex = kiwiCompatOrderedIds[idOrEl];
      return byIndex && core.record(byIndex) ? byIndex : null;
    }
    if (typeof idOrEl === "string" && core.record(idOrEl)) return idOrEl;
    if (idOrEl && idOrEl.nodeType === 1) {
      var entry = compatControlByElement.get(idOrEl);
      if (entry && core.record(entry.id)) return entry.id;
      if (idOrEl.dataset && idOrEl.dataset.kiwiInstance && core.record(idOrEl.dataset.kiwiInstance)) {
        return idOrEl.dataset.kiwiInstance;
      }
      var inner = idOrEl.querySelector ? idOrEl.querySelector("[data-kiwi-widget]") : null;
      if (inner && inner.dataset && inner.dataset.kiwiInstance && core.record(inner.dataset.kiwiInstance)) {
        return inner.dataset.kiwiInstance;
      }
    }
    return null;
  }
  var compatApi = {
    render: compatRender,
    reset: function (idOrEl) {
      var id = compatResolveId(idOrEl);
      if (id) core.reset(id);
    },
    getResponse: function (idOrEl) {
      var id = compatResolveId(idOrEl);
      return id ? core.getResponse(id) : "";
    },
    execute: compatExecute,
    remove: function (idOrEl) {
      var id = compatResolveId(idOrEl);
      if (!id) return;
      var entry = compatControlById[id] || null;
      if (entry && entry.el && entry.activationHandler) {
        try { entry.el.removeEventListener("click", entry.activationHandler); } catch (e) {}
        entry.activationHandler = null;
      }
      core.remove(id);
      // The owned holder leaves with the widget; the provider control
      // itself stays where the page put it.
      if (entry && entry.holder && entry.holder.parentNode) entry.holder.parentNode.removeChild(entry.holder);
      compatForgetControl(entry);
    },
    // Turnstile's ready() + isExpired() lifecycle surface.
    ready: function (fn) {
      if (typeof fn !== "function") return;
      (kiwiCompatGlueReady || Promise.resolve()).then(function () { try { fn(); } catch (e) {} });
    },
    isExpired: function (idOrEl) {
      var id = compatResolveId(idOrEl);
      return id ? core.isExpired(id) : false;
    }
  };
  // Merge into a pre-seeded provider global (its own properties stay);
  // ready callbacks queued before the loader drain once, in order, after
  // the glue is ready.
  var COMPAT_QUEUE_KEYS = ["_", "q", "queue", "_q", "_ready", "readyQueue"];
  function compatDrainQueue(q, queued) {
    if (Object.prototype.toString.call(q) !== "[object Array]") return;
    for (var i = 0; i < q.length; i++) {
      if (typeof q[i] === "function" && queued.indexOf(q[i]) === -1) queued.push(q[i]);
    }
    try { q.length = 0; } catch (e) {}
  }
  // Conventional reCAPTCHA pre-loader queues: callbacks parked as arrays
  // on ___grecaptcha_cfg (cfg.ready), the loader's fns/onload arrays and
  // clients.af.ready drain once; the config object stays untouched.
  function compatCollectPreloader(queued) {
    var cfg = window.___grecaptcha_cfg;
    if (!cfg || (typeof cfg !== "object" && typeof cfg !== "function")) return;
    compatDrainQueue(cfg.ready, queued);
    compatDrainQueue(cfg.fns, queued);
    compatDrainQueue(cfg.onload, queued);
    var clients = cfg.clients;
    if (clients && typeof clients === "object") {
      compatDrainQueue(clients.ready, queued);
      var af = clients.af;
      if (af && typeof af === "object") compatDrainQueue(af.ready, queued);
    }
  }
  function compatMountGlobal(name, api) {
    var existing = window[name];
    var queued = [];
    if (compat === "recaptcha" && name === "grecaptcha") compatCollectPreloader(queued);
    if (existing && (typeof existing === "object" || typeof existing === "function")) {
      for (var i = 0; i < COMPAT_QUEUE_KEYS.length; i++) {
        compatDrainQueue(existing[COMPAT_QUEUE_KEYS[i]], queued);
      }
      Object.assign(existing, api);
      window[name] = existing;
    } else {
      window[name] = api;
    }
    if (queued.length) {
      (kiwiCompatGlueReady || Promise.resolve()).then(function () {
        for (var k = 0; k < queued.length; k++) core.safeCallback(queued[k]);
      });
    }
    return window[name];
  }
  if (compat === "recaptcha") {
    compatMountGlobal("grecaptcha", Object.assign({}, compatApi, {
      // ready() queues until the compat loader's glue bootstrap
      // resolves — an explicit render() inside ready() that immediately
      // starts an Argon challenge must not race the glue handshake
      // (implicit rendering already waits).
      ready: function (fn) {
        if (typeof fn !== "function") return;
        (kiwiCompatGlueReady || Promise.resolve()).then(function () { core.safeCallback(fn); });
      },
      enterprise: undefined
    }));
  } else if (compat === "hcaptcha") {
    compatMountGlobal("hcaptcha", Object.assign({}, compatApi, {
      getRespKey: function (idOrEl) {
        // The omitted argument defaults to the FIRST created widget
        // exactly like the shared resolver. The key is the stable
        // per-widget response key assigned at render time — never the
        // response token.
        var id = compatResolveId(idOrEl);
        var rec = id ? core.record(id) : null;
        return rec ? (rec.responseKey || "") : "";
      }
    }));
  } else {
    compatMountGlobal("turnstile", compatApi);
  }
  compatInjectCss();
  // render=explicit suppresses automatic rendering; onload=<fn> runs
  // after the glue is ready. The readiness gate also queues an immediate
  // execute()/getResponse() behind the registration.
  var kiwiCompatReady = (kiwiCompatGlueReady || Promise.resolve()).then(function () {
    if (compatOnloadName) {
      var onloadFn = window[compatOnloadName];
      if (typeof onloadFn === "function") core.safeCallback(onloadFn);
    }
    if (compatRenderMode === "explicit") return;
    // Implicit render: every incumbent container on the page. The initial
    // render waits for the loader-glue bootstrap so Argon2id solves work on
    // first paint through the external /api.js path.
    var compatContainers = document.querySelectorAll(COMPAT_SELECTOR);
    for (var ci = 0; ci < compatContainers.length; ci++) {
      compatRender(compatContainers[ci], null, true);
    }
  });
  // A removed provider element whose widget record survives leaks its
  // holder and its challenge lifecycle. The connectedness read waits a
  // microtask, so a same-task reparent (remove + reinsert) keeps the
  // widget; only a truly detached element is torn down.
  function compatTeardownIfDetached(el) {
    Promise.resolve().then(function () {
      if (el.isConnected) return;
      var entry = compatControlByElement.get(el);
      if (!entry) return;
      if (entry.activationHandler) {
        try { el.removeEventListener("click", entry.activationHandler); } catch (e) {}
        entry.activationHandler = null;
      }
      if (entry.id && core.record(entry.id)) core.remove(entry.id);
      if (entry.holder && entry.holder.parentNode) entry.holder.parentNode.removeChild(entry.holder);
      compatForgetControl(entry);
    });
  }
  function compatCollectRemovals(removed) {
    if (!removed || !removed.length) return;
    for (var i = 0; i < removed.length; i++) {
      var node = removed[i];
      if (!node || node.nodeType !== 1) continue;
      if (compatControlByElement.has(node)) compatTeardownIfDetached(node);
      if (node.querySelectorAll) {
        var tracked = node.querySelectorAll("button,input,[data-size='invisible'],.g-recaptcha,.h-captcha,.cf-turnstile");
        for (var j = 0; j < tracked.length; j++) {
          if (compatControlByElement.has(tracked[j])) compatTeardownIfDetached(tracked[j]);
        }
      }
    }
  }
  // Dynamic implicit rendering (never in explicit mode): the whole added
  // subtree is traversed for every provider, so nested containers and
  // late controls render and bind. Removals tear down detached controls.
  if (compatRenderMode !== "explicit" && typeof MutationObserver !== "undefined") {
    new MutationObserver(function (mutations) {
      for (var m = 0; m < mutations.length; m++) {
        var nodes = mutations[m].addedNodes;
        for (var n = 0; n < nodes.length; n++) {
          var node = nodes[n];
          if (!node || node.nodeType !== 1) continue;
          if (node.matches && node.matches(COMPAT_SELECTOR)) compatRender(node, null, true);
          if (node.querySelectorAll) {
            var nested = node.querySelectorAll(COMPAT_SELECTOR);
            for (var q = 0; q < nested.length; q++) compatRender(nested[q], null, true);
          }
        }
        compatCollectRemovals(mutations[m].removedNodes);
      }
    }).observe(document.body || document.documentElement, { childList: true, subtree: true });
  }
})();
