(function () {
  // ── widget-compat.js: the incumbent compatibility loader ───────────
  // The driver core doubles as the first-party compatibility loader
  // only in the sense that it detects the loader context; ALL the
  // incumbent machinery lives in this lazy module, which is delivered
  // INSIDE the /api.js loader response (glue + widget-driver.js core +
  // widget-compat.js, concatenated by the bundle's ApiJsController and
  // split by the /*KIWI_COMPAT_SPLIT*/ marker) — so it executes only on
  // the compatibility route, never on an ordinary widget page, and the
  // eager core stays free of the compat surface. When the driver script
  // itself is loaded as .../api.js?compat=recaptcha (or
  // hcaptcha/turnstile), this module auto-renders the incumbent
  // containers (.g-recaptcha/.h-captcha/.cf-turnstile), installs the
  // provider global, and keeps the provider-named response field in
  // sync with the same underlying Kiwi solution token. An incumbent
  // page changes only its provider script URL.
  //
  // The module parses its own script URL for the loader parameters
  // (?compat= / render= / onload= / hl=) — inside the /api.js response
  // the script element is the api.js element itself, exactly the URL
  // the historical driver parsed — and calls back into the core through
  // the bridge (the core closure state is not shared — the bridge is
  // the module boundary). Executed on a page whose script URL carries
  // no compat parameter (never the delivered layout), the module stays
  // inert.
  var K = (typeof window !== "undefined" && window.__kiwiCaptchaCore) || null;
  if (!K || !K.core) return;
  var core = K.core;

  // ONE coherent loader parser — URLSearchParams (no regexes): compat,
  // render, onload, hl, with callback-identifier validation and locale
  // normalization.
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
  // Google's API defaults reset()/getResponse() and invisible execute()
  // to the FIRST CREATED widget when the id is omitted. Track the first
  // successful compat render.
  var kiwiCompatFirstId = null;
  // The loader's own glue part (the /api.js response is glue + driver +
  // this module, split by the /*KIWI_COMPAT_SPLIT*/ marker): the worker
  // cannot find the glue in an inline script element, so the module
  // fetches the loader's own source once and keeps the glue part for
  // the Blob-worker prelude — Argon2id stays worker-only and WORKING
  // through the external loader. The glue is handed to the core bridge
  // (K.compatGlue), where the worker path reads it.
  var kiwiCompatGlue = null;
  var kiwiCompatGlueReady = null;
  // Revalidate — force-cache would let the browser reuse a stale
  // /api.js representation, defeating the server's ETag policy and
  // potentially pairing the current driver with an out-of-date glue
  // of the same protocol generation.
  kiwiCompatGlueReady = fetch(compatScriptUrl.split("?")[0], { cache: "no-cache", credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.text() : null; })
    .then(function (src) {
      if (!src) return;
      var idx = src.indexOf("/*KIWI_COMPAT_SPLIT*/");
      if (idx !== -1) {
        kiwiCompatGlue = src.slice(0, idx);
        if (K) K.compatGlue = kiwiCompatGlue;
      }
    })
    .catch(function () {});

  var COMPAT_FIELD = { recaptcha: "g-recaptcha-response", hcaptcha: "h-captcha-response", turnstile: "cf-turnstile-response" }[compat];
  var COMPAT_SELECTOR = { recaptcha: ".g-recaptcha", hcaptcha: ".h-captcha", turnstile: ".cf-turnstile" }[compat];
  var COMPAT_SVG = '<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M26 19c0 5.5-4 10-10 10S7 24.5 7 19c0-6 3-11 7-12 2-0.5 4-0.5 6 0 4 1 6 6 6 12z" fill="currentColor"/><path d="M12.5 8.5c-.8-1.5-1-3.5-.5-5.5.5-2 2-3.5 4-4 2-.5 4 .5 5 2.5.2 1 .5 2 .5 3.5" fill="currentColor"/><path d="M10 7c-4 1-8 3-8.5 3.5-.3.3-.3.8 0 1 1 0.5 8 2.5 9.5 2.5" fill="currentColor"/><path d="M14 29v2m6-2v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/><circle cx="16.5" cy="4.5" r="1" fill="white"/><circle cx="17" cy="4" r="0.6" fill="currentColor"/><path d="M19 14c1.5 0 2.5 1 2.5 2s-1 2-2.5 2-2.5-1-2.5-2 1-2 2.5-2z" fill="white" opacity="0.2"/></svg>';
  function compatInjectCss() {
    if (!compatScriptUrl || document.querySelector('link[data-kiwi-css]')) return;
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.setAttribute("data-kiwi-css", "");
    var base = compatScriptUrl.split("?")[0];
    link.href = base.substring(0, base.lastIndexOf("/") + 1) + "widget.css";
    document.head.appendChild(link);
  }
  // The /api.js loader response carries the content-addressed
  // widget-locales.js descriptor (the server computes the hash and the
  // SRI digest of the exact module bytes; see ApiJsController). The
  // compat markup issues it as data-kiwi-locales-src / data-kiwi-
  // locales-integrity on the rendered container, so the core lazy-
  // fetches the non-default packs only when the resolved language
  // needs them. The compat tier embeds its other modules, but locale
  // strings stay lazy: an English page pays zero bytes for
  // translations.
  var compatLocales = (typeof window !== "undefined" && window.__kiwiCaptchaCompatLocales) || null;
  var compatLocalesAttrs = "";
  var compatLocalesSrc = "";
  if (compatLocales && compatScriptUrl) {
    var compatBase = compatScriptUrl.split("?")[0];
    compatBase = compatBase.substring(0, compatBase.lastIndexOf("/") + 1);
    compatLocalesSrc = compatBase + 'assets/locales.' + compatLocales.hash + '.js';
    compatLocalesAttrs = ' data-kiwi-locales-src="' + compatLocalesSrc + '"'
      + ' data-kiwi-locales-integrity="' + compatLocales.sri + '"';
  }
  function compatMarkup() {
    return '<div class="kiwi-container"' + compatLocalesAttrs + '><input type="hidden" name="kiwi__token" data-kiwi-token value="">' +
      '<div class="kiwi-widget" data-kiwi-widget data-kiwi-started="1" data-state="idle" role="group" aria-label="KiwiCaptcha security check">' +
      '<div class="kiwi-icon-wrapper" aria-hidden="true">' + COMPAT_SVG + '<div class="kiwi-glow"></div></div>' +
      '<div class="kiwi-main"><div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>' +
      '<div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>' +
      '<div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected by KiwiCaptcha</p><span class="kiwi-timer" data-kiwi-timer></span></div></div>' +
      '<span class="kiwi-sr-only" data-kiwi-status role="status" aria-live="polite"></span></div></div>';
  }
  function compatReadCallbacks(el, params) {
    var cb = function (name) {
      var v = (params && (params[name] !== undefined)) ? params[name]
        : (el.getAttribute("data-" + name.replace(/([A-Z])/g, "-$1").toLowerCase()) || "");
      return typeof v === "function" ? v : (typeof v === "string" && v ? (window[v] || null) : null);
    };
    return {
      callback: cb("callback"),
      expiredCallback: cb("expired-callback"),
      errorCallback: cb("error-callback")
    };
  }
  function compatRender(target, params) {
    // grecaptcha.render("id", ...) / render(selector, ...) resolve
    // through the same target resolver as the native API and return a
    // working widget id.
    var el = core.resolveTarget(target);
    if (!el || el.nodeType !== 1) return 0;
    // Re-rendering an already-rendered container must be idempotent —
    // the existing widget instance is returned instead of
    // double-initializing the same container (a second solve on the
    // same element would race the first). initWidget keys the instance
    // on the CONTAINER (el.dataset.kiwiInstance); the inner
    // [data-kiwi-widget] markup carries no instance id of its own.
    if (el.dataset.kiwiInstance && core.record(el.dataset.kiwiInstance)) {
      return el.dataset.kiwiInstance;
    }
    var existingWidget = el.querySelector ? el.querySelector("[data-kiwi-widget]") : null;
    if (existingWidget && existingWidget.dataset.kiwiInstance && core.record(existingWidget.dataset.kiwiInstance)) {
      return existingWidget.dataset.kiwiInstance;
    }
    if (!el.querySelector("[data-kiwi-widget]")) {
      if (el.tagName === "BUTTON" || el.tagName === "INPUT") {
        // Invisible-style controls keep their label; the widget is
        // appended (reCAPTCHA renders inside the control the same way).
        el.insertAdjacentHTML("beforeend", compatMarkup());
      } else {
        el.innerHTML = compatMarkup();
      }
    }
    // Pass through explicit Kiwi overrides (e.g.
    // data-kiwi-endpoint="/challenge?ttl=2") from the incumbent
    // container onto the rendered widget container; the endpoint
    // defaults to the bundle's same-origin prefix so a migrated page
    // needs NO endpoint configuration.
    var inner = el.querySelector(".kiwi-container");
    if (inner) {
      ["data-kiwi-endpoint", "data-kiwi-scope", "data-kiwi-algorithm", "data-kiwi-worker-src", "data-kiwi-locales-src", "data-kiwi-locales-integrity"].forEach(function (attr) {
        if (el.hasAttribute(attr) && !inner.hasAttribute(attr)) inner.setAttribute(attr, el.getAttribute(attr));
      });
      if (!inner.hasAttribute("data-kiwi-endpoint")) inner.setAttribute("data-kiwi-endpoint", "/kiwi-captcha/challenge");
      // The driver reads module attrs from the rendered container AND
      // its own element; mirror the loader-issued locales attrs onto
      // the element when the page left them unset.
      if (compatLocalesSrc && !el.hasAttribute("data-kiwi-locales-src")) {
        el.setAttribute("data-kiwi-locales-src", compatLocalesSrc);
        el.setAttribute("data-kiwi-locales-integrity", compatLocales.sri);
      }
      // The driver reads the endpoint from the rendered container AND
      // from its own ancestor chain — mirror the default onto the
      // incumbent container so a page with NO explicit endpoint uses
      // the bundle's same-origin prefix (the one-line migration
      // contract relies on this default).
      if (!el.hasAttribute("data-kiwi-endpoint")) el.setAttribute("data-kiwi-endpoint", "/kiwi-captcha/challenge");
    }
    var sitekey = (params && (params.sitekey || params["sitekey"])) || el.getAttribute("data-sitekey") || "";
    var cbs = compatReadCallbacks(el, params);
    var id = core.render(el, {
      scope: sitekey || "login",
      callback: cbs.callback,
      expiredCallback: cbs.expiredCallback,
      errorCallback: cbs.errorCallback,
      // Turnstile's configurable response field (response-field-name /
      // params["response-field-name"]) — the default stays the
      // provider-named field. response-field=false keeps the internal
      // Kiwi token field and SKIPS the provider alias input;
      // response-field-name overrides the alias name.
      responseField: (params && params["response-field"] === false)
        || el.getAttribute("data-response-field") === "false"
        ? false
        : ((params && typeof params["response-field-name"] === "string" && params["response-field-name"])
          || el.getAttribute("data-response-field-name") || COMPAT_FIELD),
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
      // Turnstile language + the public sitekey (server-owned scope
      // resolution). The loader's own hl= parameter (parsed by the
      // core from this script's URL) is the lowest-precedence language
      // fallback, exactly where the historical driver consulted it.
      language: (params && typeof params.language === "string" && params.language)
        || el.getAttribute("data-language")
        || (compatLoader && compatLoader.language) || undefined,
      // Explicit-execution mode: params.execution="execute" or
      // data-execution="execute" on the container defers the challenge
      // until execute() (params win over the attribute).
      execution: (params && typeof params.execution === "string")
        ? params.execution
        : (el.getAttribute("data-execution") === "execute" ? "execute" : undefined),
      sitekey: sitekey || undefined
    });
    if (id && !kiwiCompatFirstId) kiwiCompatFirstId = id;
    return id || 0;
  }
  // hCaptcha async execute() rejects with a stable error-code STRING
  // (network-error | challenge-error | internal-error) that migrated
  // applications branch on like the incumbent API. Map the driver's
  // underlying rejection to that code — the message text is the stable
  // signal, because fail() forwards e.message into a fresh Error:
  // transport failures (aborted fetches, fetch TypeErrors, non-2xx
  // challenge responses) -> "network-error"; challenge-content and
  // solve failures (malformed challenge payloads, downgraded
  // challenges, exhausted searches) -> "challenge-error"; everything
  // else (worker/solver conditions, unknown widget ids) ->
  // "internal-error". The bare non-async execute keeps rejecting with
  // Error objects.
  function kiwiHcaptchaErrorCode(err) {
    var name = err && err.name;
    if (name === "AbortError" || name === "TypeError") return "network-error";
    var lower = String((err && err.message) || "").toLowerCase();
    if (lower.indexOf("abort") !== -1 || lower.indexOf("fetch") !== -1 || lower.indexOf("network") !== -1 || lower.indexOf("load failed") !== -1 || lower.indexOf("challenge failed") !== -1) return "network-error";
    if (lower.indexOf("solve") !== -1 || lower.indexOf("downgrad") !== -1 || lower.indexOf("exhaust") !== -1 || lower.indexOf("challenge malformed") !== -1) return "challenge-error";
    return "internal-error";
  }
  function compatExecute(arg, opts) {
    // Registration readiness first: implicit compat renders complete
    // asynchronously (the loader-glue bootstrap), so execute() awaits
    // kiwiCompatReady before resolving its target — an immediate
    // execute must observe the rendered widget, not a widget-less
    // page.
    return (kiwiCompatReady || Promise.resolve()).then(function () {
    // The hCaptcha async mode ({async:true}) is determined BEFORE
    // argument resolution: the async form normalizes BOTH resolution
    // failures — "missing-captcha" (no widget exists) and
    // "invalid-captcha-id" (the target resolves to nothing) — and the
    // execution outcome ({response, key} / error-code STRING). The
    // other providers and the bare (non-async) hCaptcha execute keep
    // Error-object rejections and the v3 sitekey path.
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
      // Argument resolution order: a widget id, then an element id, then
      // a selector matching an existing rendered container. Only a string
      // that matches NONE of those can be a v3-style sitekey — and the
      // hidden-holder v3 path is reCAPTCHA-only; Turnstile and hCaptcha
      // reject unresolvable targets instead of fabricating a widget.
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
        // hCaptcha async rejects an unresolvable target (not a widget
        // id, element or container selector) with the incumbent's
        // "invalid-captcha-id" STRING.
        return Promise.reject("invalid-captcha-id");
      }
    }
    if (id) {
      var execPromise = core.execute(id);
      if (hcaptchaAsync) {
        // hCaptcha async execute: resolve with the token AND the stable
        // per-widget response key ({response, key}); the bare non-async
        // form resolves the token string. Rejections are normalized to
        // the incumbent's stable error-code STRING (see
        // kiwiHcaptchaErrorCode) — an Error object is never surfaced
        // through the async form.
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
    // v3-style execute(sitekey, {action}): map action -> Kiwi scope on a
    // hidden widget. Honest v3 handling: no fabricated score is ever
    // produced — the application migrates to Kiwi verification plus the
    // optional adaptive-risk decision machinery.
    var sitekey = typeof arg === "string" ? arg : "";
    var action = (opts && opts.action) || sitekey || "login";
    var holder = document.createElement("div");
    holder.style.display = "none";
    var inner = document.createElement("div");
    inner.className = "kiwi-container";
    inner.setAttribute("data-kiwi-scope", action);
    holder.appendChild(inner);
    document.body.appendChild(holder);
    // Render through compatRender so the same endpoint/scope/response-
    // field defaults land on the holder (an explicit native-default
    // endpoint would 404 on a compat deployment). The REAL sitekey and
    // the requested action are transmitted INDEPENDENTLY — the action
    // is never passed as the sitekey, so the server-owned (sitekey,
    // action) -> scope policy stays connected.
    var id2 = compatRender(inner, { sitekey: sitekey, action: action });
    if (!id2) {
      if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
      return Promise.reject(new Error("kiwicaptcha: hidden render failed"));
    }
    var p = core.execute(id2);
    // A long-lived SPA repeatedly calling execute() must not accumulate
    // hidden DOM, registry entries or reset hooks — the holder is
    // removed and the widget destroyed on BOTH paths.
    if (p && typeof p.then === "function") {
      return p.then(function (tok) {
        if (id2 && core.record(id2)) core.remove(id2);
        if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
        return tok;
      }, function (err) {
        if (id2 && core.record(id2)) core.remove(id2);
        if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
        throw err;
      });
    }
    return p;
    });
  }
  function compatResolveId(idOrEl) {
    // An OMITTED id targets the first created widget (the incumbent
    // providers' documented default); an element resolves to its
    // rendered widget instance (the element's own data-kiwi-instance is
    // the widget id in compat mode, where the container carries it).
    if (idOrEl === undefined || idOrEl === null) return kiwiCompatFirstId;
    if (typeof idOrEl === "string" && core.record(idOrEl)) return idOrEl;
    if (idOrEl && idOrEl.nodeType === 1) {
      if (idOrEl.dataset && idOrEl.dataset.kiwiInstance && core.record(idOrEl.dataset.kiwiInstance)) {
        return idOrEl.dataset.kiwiInstance;
      }
      if (idOrEl.querySelector) {
        return (idOrEl.querySelector("[data-kiwi-widget]") || {}).dataset.kiwiInstance || null;
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
      if (id) core.remove(id);
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
  if (compat === "recaptcha") {
    window.grecaptcha = window.grecaptcha || Object.assign({}, compatApi, {
      // ready() queues until the compat loader's glue self-fetch
      // resolves — an explicit render() inside ready() that immediately
      // starts an Argon challenge must not race the glue bootstrap
      // (implicit rendering already waits).
      ready: function (fn) {
        if (typeof fn !== "function") return;
        (kiwiCompatGlueReady || Promise.resolve()).then(function () { core.safeCallback(fn); });
      },
      enterprise: undefined
    });
  } else if (compat === "hcaptcha") {
    window.hcaptcha = window.hcaptcha || Object.assign({}, compatApi, {
      getRespKey: function (idOrEl) {
        // The omitted argument defaults to the FIRST created widget
        // exactly like the shared resolver. The key is the stable
        // per-widget response key assigned at render time — never the
        // response token.
        var id = compatResolveId(idOrEl);
        var rec = id ? core.record(id) : null;
        return rec ? (rec.responseKey || "") : "";
      }
    });
  } else {
    window.turnstile = window.turnstile || compatApi;
  }
  compatInjectCss();
  // render=explicit suppresses automatic rendering — the application
  // calls render() itself (the documented explicit pattern); onload=<fn>
  // runs after the loader glue is ready so an immediate explicit Argon
  // render can never race the glue bootstrap.
  // The compat readiness gate: implicit renders happen after the
  // loader-glue bootstrap, so an immediate execute()/getResponse() must
  // await the registration. An execute racing the registration would
  // resolve a widget-less target ("missing-captcha" / "invalid-captcha-
  // id") instead of the real network outcome — the lifecycle race the
  // browser suite exercises with the challenge endpoint down.
  var kiwiCompatReady = (kiwiCompatGlueReady || Promise.resolve()).then(function () {
    if (compatOnloadName) {
      var onloadFn = window[compatOnloadName];
      if (typeof onloadFn === "function") core.safeCallback(onloadFn);
    }
    if (compatRenderMode === "explicit") return;
    // Implicit render: every incumbent container on the page. The initial
    // render waits for the loader-glue fetch so Argon2id solves work on
    // first paint through the external /api.js path.
    var compatContainers = document.querySelectorAll(COMPAT_SELECTOR);
    for (var ci = 0; ci < compatContainers.length; ci++) {
      var el = compatContainers[ci];
      var wid = compatRender(el);
      // Invisible-style controls (buttons / inputs / data-size="invisible"):
      // clicking the control triggers execute() — the incumbent pattern.
      if (wid && (el.tagName === "BUTTON" || el.tagName === "INPUT" || el.getAttribute("data-size") === "invisible")) {
        (function (id, node) {
          node.addEventListener("click", function (ev) {
            ev.preventDefault();
            core.execute(id);
          });
        })(wid, el);
      }
    }
  });
  // Dynamic implicit-render convenience: a .g-recaptcha node inserted
  // later is auto-rendered — NEVER in explicit mode: render=explicit
  // means the application controls rendering (Google's documented
  // contract), so a later container must stay untouched until an
  // explicit grecaptcha.render() call.
  if (compat === "recaptcha" && compatRenderMode !== "explicit" && typeof MutationObserver !== "undefined") {
    new MutationObserver(function (mutations) {
      for (var m = 0; m < mutations.length; m++) {
        var nodes = mutations[m].addedNodes;
        for (var n = 0; n < nodes.length; n++) {
          var node = nodes[n];
          if (node && node.nodeType === 1 && node.matches && node.matches(COMPAT_SELECTOR) && !node.querySelector("[data-kiwi-widget]")) {
            compatRender(node);
          }
        }
      }
    }).observe(document.body, { childList: true, subtree: true });
  }
})();
