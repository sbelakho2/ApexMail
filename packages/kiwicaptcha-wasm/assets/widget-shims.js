(function () {
  // ── widget-shims.js: the standalone incumbent API shims ───────────
  // Installs window.grecaptcha, window.hcaptcha and window.turnstile
  // over an ORDINARY widget bootstrap (the driver bridge), so an
  // application that hardcodes the provider globals keeps working once
  // the provider script URL points at KiwiCaptcha. The compat loader
  // (widget-compat.js, delivered inside the /api.js?compat=... route)
  // covers the incumbent container markup; this asset covers the
  // provider GLOBALS on a plain driver page and recognizes the Altcha
  // and Friendly Captcha element conventions so their existing markup
  // keeps working.
  //
  // v2/v3 semantics: render() without an action renders the v2 form
  // (the interactive widget starts on its own activation); a call whose
  // params carry an invisible size, or a BUTTON/INPUT target, defers
  // the run to execute() exactly like the incumbent invisible control.
  // execute(sitekey, {action}) against a bare sitekey string is the v3
  // form: a hidden widget is created for the call, solved, removed, and
  // the promise carries the token (no score is fabricated).
  //
  // Scope mapping knobs (read from data-attributes): data-kiwi-scope on
  // a container is the exact scope and wins over every heuristic; the
  // page-level sitekey table rides the shim script tag as
  // data-kiwi-scope-map (a JSON object of sitekey -> scope); an
  // unmapped sitekey is presented verbatim so the deployment's
  // server-side sitekey allowlist resolves it; nothing at all resolves
  // to the v2 default scope "login". The action suffix rule
  // (data-kiwi-scope-action="1" on the container, or params.scopeAction)
  // appends ":<action>" to the resolved scope when an action is
  // presented; otherwise the action rides the challenge request and the
  // server's (sitekey, action) policy resolves it.
  var SHIMS_QUEUES = ["_", "q", "queue", "_q", "_ready", "readyQueue"];
  var SHIMS_FORBIDDEN_CALLBACKS = {
    eval: true, Function: true, constructor: true, __proto__: true, prototype: true,
    setTimeout: true, setInterval: true, setImmediate: true, requestAnimationFrame: true,
  };
  var SHIMS_SVG = '<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" stroke-width="6.6" stroke-linecap="round" stroke-linejoin="round" fill="none"><path d="M32 42 C32 35 43 35 43 42 C43 51 29 54 23 46 C16 36 25 28 35 29 C47 29 54 38 53 46 C52 56 43 60 31 59 C17 58 9 51 10 41 C10 33 16 28 21 28"/><path d="M22 25 V16 A10 10 0 0 1 42 16 V25"/></g></svg>';
  var shimsScriptUrl = null;
  var shimsScriptEl = null;
  var shimsScopeMapCache = null;
  var shimsOrderedIds = [];
  var shimsFirstId = null;
  var shimsMounted = false;
  // Owned control bindings: a button or input control renders into an
  // adjacent holder, and this table backs remove() and the owned
  // activation listener.
  var shimsControlByElement = new WeakMap();
  // Null-prototype: the key is the widget render id (page-influenced).
  var shimsControlById = Object.create(null);
  try {
    var shimsScript = document.currentScript;
    if (!shimsScript) {
      var shimsScripts = document.getElementsByTagName("script");
      shimsScript = shimsScripts[shimsScripts.length - 1];
    }
    shimsScriptEl = shimsScript || null;
    shimsScriptUrl = shimsScript && shimsScript.src ? shimsScript.src : null;
  } catch (e) {}
  var shimsAssetBase = shimsScriptUrl ? shimsScriptUrl.split("?")[0].replace(/[^/]*$/, "") : "/";
  var shimsRouteBase = "/";
  try { shimsRouteBase = new URL(shimsScriptUrl || "/", document.baseURI).pathname.replace(/[^/]*$/, ""); } catch (e) {}
  var shimsEndpointDefault = shimsRouteBase + "challenge";
  function shimsInjectCss() {
    if (!shimsScriptUrl || document.querySelector('link[data-kiwi-css]')) return;
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.setAttribute("data-kiwi-css", "");
    link.href = shimsAssetBase + "widget.css";
    document.head.appendChild(link);
  }
  // The page-level sitekey table: data-kiwi-scope-map on the shim's own
  // script tag, parsed once. A malformed document leaves the table
  // empty (the sitekey then travels verbatim), never throws.
  function shimsScopeMap() {
    if (shimsScopeMapCache !== null) return shimsScopeMapCache;
    // Null-prototype: keys come from the page's data-kiwi-scope-map JSON.
    shimsScopeMapCache = Object.create(null);
    try {
      var el = shimsScriptEl;
      var raw = el && el.getAttribute ? el.getAttribute("data-kiwi-scope-map") : null;
      if (typeof raw !== "string" || !raw) return shimsScopeMapCache;
      var parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        for (var k in parsed) {
          if (Object.prototype.hasOwnProperty.call(parsed, k)
            && typeof parsed[k] === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(parsed[k])) {
            shimsScopeMapCache[k] = parsed[k];
          }
        }
      }
    } catch (e) {}
    return shimsScopeMapCache;
  }
  // The one knob resolver: explicit scope wins, then the page table,
  // then the verbatim sitekey, then the v2 default. The optional
  // suffix rule appends the action to the scope itself.
  function shimsResolveMeta(el, params) {
    params = params || {};
    var attr = function (name) { return (el && el.getAttribute) ? el.getAttribute(name) : null; };
    var sitekey = (params.sitekey && String(params.sitekey)) || attr("data-sitekey") || "";
    var explicit = (typeof params.scope === "string" && params.scope) || attr("data-kiwi-scope") || "";
    var action = (typeof params.action === "string" && params.action) || attr("data-action") || "";
    var cData = (typeof params.cData === "string" && params.cData) || attr("data-cdata") || "";
    var map = shimsScopeMap();
    var scope = explicit || map[sitekey] || sitekey || "login";
    var suffix = attr("data-kiwi-scope-action") === "1" || params.scopeAction === true;
    if (action && suffix) scope = scope + ":" + action;
    return { scope: scope, sitekey: sitekey, action: action, cData: cData };
  }
  function shimsMarkup() {
    return '<div class="kiwi-container"><input type="hidden" name="kiwi__token" data-kiwi-token value="">' +
      '<div class="kiwi-widget" data-kiwi-widget data-kiwi-started="1" data-state="idle" role="group" aria-label="KiwiCaptcha security check">' +
      '<div class="kiwi-icon-wrapper" aria-hidden="true">' + SHIMS_SVG + '</div>' +
      '<div class="kiwi-main"><div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>' +
      '<div class="kiwi-slots" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div><div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>' +
      '<div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected by KiwiCaptcha</p><span class="kiwi-timer" data-kiwi-timer></span></div></div>' +
      '<span class="kiwi-sr-only" data-kiwi-status role="status" aria-live="polite"></span></div></div>';
  }
  // Callback names resolve via own-property window lookups only: the
  // platform constructors and code-evaluation entries stay unreachable.
  function shimsReadCallbacks(el, params) {
    var cb = function (name) {
      var v = (params && (params[name] !== undefined)) ? params[name]
        : (el.getAttribute ? el.getAttribute("data-" + name.replace(/([A-Z])/g, "-$1").toLowerCase()) : null);
      if (typeof v === "function") return v;
      if (typeof v !== "string" || !v) return null;
      if (SHIMS_FORBIDDEN_CALLBACKS[v]) return null;
      if (!Object.prototype.hasOwnProperty.call(window, v)) return null;
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
  // The incumbent renders its response field(s) at render time; the
  // fields are hidden textareas carrying the incumbent's exact id and
  // name, so markup reading either attribute keeps working. The hCaptcha
  // surface always creates both provider fields.
  function shimsEnsureResponseFields(host, names) {
    if (!host) return;
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) continue;
      var existing = host.querySelectorAll('input[name="' + name + '"],textarea[name="' + name + '"]');
      if (existing.length) continue;
      var field = document.createElement("textarea");
      field.id = name;
      field.name = name;
      field.className = "g-recaptcha-response";
      field.setAttribute("data-kiwi-response-alias", "");
      field.style.display = "none";
      host.appendChild(field);
    }
  }
  function shimsIsControl(el) {
    return !!el && (el.tagName === "BUTTON" || el.tagName === "INPUT");
  }
  function shimsIsInvisible(el, params) {
    if (shimsIsControl(el)) return true;
    if (el && el.getAttribute && el.getAttribute("data-size") === "invisible") return true;
    if (params && (params.size === "invisible" || params.type === "invisible")) return true;
    return false;
  }
  function shimsForgetControl(entry) {
    if (!entry) return;
    if (entry.el) shimsControlByElement.delete(entry.el);
    if (entry.id && shimsControlById[entry.id] === entry) delete shimsControlById[entry.id];
  }
  function shimsBindActivation(el, id) {
    var entry = shimsControlByElement.get(el);
    if (!entry || entry.id !== id || entry.activationHandler) return;
    entry.activationHandler = function (ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      // Fire-and-forget: failures surface via the error lifecycle only.
      Promise.resolve(window.__kiwiCaptchaCore.core.execute(entry.id)).catch(function () {});
    };
    el.addEventListener("click", entry.activationHandler);
  }
  // render(target, params, provider): the one render implementation
  // shared by every provider surface and the implicit scan. A control
  // target (a button or input) renders into an adjacent holder, never
  // nested interactive content.
  function shimsRender(provider, target, params, implicit) {
    var core = window.__kiwiCaptchaCore.core;
    var el = core.resolveTarget(target);
    if (!el || el.nodeType !== 1) return 0;
    if (!implicit && core.clearModuleBackoff) core.clearModuleBackoff();
    // Idempotent re-render: a second solve on one element would race
    // the first, so the live record wins.
    var boundEntry = shimsControlByElement.get(el);
    if (boundEntry && core.record(boundEntry.id)) return boundEntry.id;
    if (el.dataset.kiwiInstance && core.record(el.dataset.kiwiInstance)) {
      return el.dataset.kiwiInstance;
    }
    var existing = el.querySelector ? el.querySelector("[data-kiwi-widget]") : null;
    if (existing && existing.dataset.kiwiInstance && core.record(existing.dataset.kiwiInstance)) {
      return existing.dataset.kiwiInstance;
    }
    var isControl = shimsIsControl(el);
    var renderTarget = el;
    var holder = null;
    if (isControl) {
      var prior = shimsControlByElement.get(el);
      if (prior && prior.holder && prior.holder.parentNode) {
        holder = prior.holder;
      } else {
        holder = document.createElement("div");
        holder.className = "kiwi-compat-holder";
        holder.setAttribute("data-kiwi-compat-holder", "");
        if (el.parentNode) el.parentNode.insertBefore(holder, el.nextSibling);
      }
      renderTarget = holder;
    }
    if (!renderTarget.querySelector("[data-kiwi-widget]")) renderTarget.innerHTML = shimsMarkup();
    if (!renderTarget.hasAttribute("data-kiwi-endpoint")) {
      renderTarget.setAttribute("data-kiwi-endpoint", shimsEndpointDefault);
    }
    var meta = shimsResolveMeta(el, params);
    var cbs = shimsReadCallbacks(el, params);
    var responseFieldName = provider;
    if (params && params["response-field"] === false) {
      responseFieldName = null;
    } else if (params && typeof params["response-field-name"] === "string" && params["response-field-name"]) {
      responseFieldName = params["response-field-name"];
    } else if (provider === "altcha") {
      responseFieldName = (el.getAttribute && el.getAttribute("name")) || "altcha";
    } else if (provider === "recaptcha") {
      responseFieldName = "g-recaptcha-response";
    } else if (provider === "hcaptcha") {
      responseFieldName = "h-captcha-response";
    } else if (provider === "turnstile") {
      responseFieldName = "cf-turnstile-response";
    } else if (provider === "friendly") {
      responseFieldName = "frc-captcha-solution";
    }
    var responseNames = responseFieldName ? [responseFieldName] : [];
    if (provider === "hcaptcha" && responseNames.indexOf("g-recaptcha-response") === -1) {
      responseNames.push("g-recaptcha-response");
    }
    var tokenHost = null;
    try { tokenHost = (renderTarget.querySelector("[data-kiwi-token]") || {}).parentNode; } catch (e) {}
    shimsEnsureResponseFields(tokenHost, responseNames);
    var deferred = (params && params.execution === "execute")
      || shimsIsInvisible(el, params)
      || (provider === "altcha" && el.getAttribute && el.getAttribute("data-auto") === "off")
      || (provider === "friendly" && el.getAttribute && el.getAttribute("data-start") !== null
        && el.getAttribute("data-start") !== "auto");
    var id = (implicit && core.renderImplicit ? core.renderImplicit : core.render)(renderTarget, {
      scope: meta.scope,
      sitekey: meta.sitekey || undefined,
      action: meta.action || undefined,
      cData: meta.cData || undefined,
      callback: cbs.callback,
      expiredCallback: cbs.expiredCallback,
      errorCallback: cbs.errorCallback,
      responseField: responseFieldName || false,
      lang: (params && typeof params.lang === "string" && params.lang)
        || (el.getAttribute && el.getAttribute("data-kiwi-lang")) || undefined,
      language: (params && typeof params.language === "string" && params.language)
        || (el.getAttribute && el.getAttribute("data-language")) || undefined,
      execution: deferred ? "execute" : undefined
    });
    if (id) {
      if (isControl) {
        var entry = shimsControlByElement.get(el);
        if (!entry) {
          entry = { el: el, id: null, holder: holder, activationHandler: null };
          shimsControlByElement.set(el, entry);
        }
        entry.id = id;
        entry.holder = holder;
        shimsControlById[id] = entry;
        shimsBindActivation(el, id);
      }
      if (!shimsFirstId) shimsFirstId = id;
      if (shimsOrderedIds.indexOf(id) === -1) shimsOrderedIds.push(id);
    } else if (isControl) {
      if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
      shimsForgetControl(shimsControlByElement.get(el));
    }
    return id || 0;
  }
  // Omitted id -> first render; number -> creation-order index; element
  // -> the owned record then the instance marker. A container without a
  // live widget resolves null, never throwing.
  function shimsResolveId(idOrEl) {
    var core = window.__kiwiCaptchaCore.core;
    if (idOrEl === undefined || idOrEl === null) return shimsFirstId;
    if (typeof idOrEl === "number" && Number.isInteger(idOrEl)) {
      var byIndex = shimsOrderedIds[idOrEl];
      return byIndex && core.record(byIndex) ? byIndex : null;
    }
    if (typeof idOrEl === "string" && core.record(idOrEl)) return idOrEl;
    if (idOrEl && idOrEl.nodeType === 1) {
      var entry = shimsControlByElement.get(idOrEl);
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
  function shimsExecute(provider, arg, opts) {
    var core = window.__kiwiCaptchaCore.core;
    var id = null;
    if (arg === undefined || arg === null) {
      id = shimsResolveId(null);
      if (!id) return Promise.reject(new Error("kiwicaptcha: no widget has been rendered"));
    } else if (typeof arg === "string" && core.record(arg)) {
      id = arg;
    } else {
      var targetEl = null;
      if (typeof arg === "string") {
        try { targetEl = document.getElementById(arg); } catch (e) {}
        if (!targetEl) {
          try {
            var matches = document.querySelectorAll(arg);
            targetEl = matches.length ? matches[0] : null;
          } catch (e) {}
        }
      } else if (arg && arg.nodeType === 1) {
        targetEl = arg;
      }
      if (targetEl) id = shimsResolveId(targetEl);
    }
    if (id) {
      var execPromise = core.execute(id);
      // The hCaptcha async form resolves {response, key} and rejects
      // with the incumbent's error-code STRING, never an Error object.
      if (provider === "hcaptcha" && opts && opts.async === true) {
        return execPromise.then(function (token) {
          var rec = core.record(id);
          return { response: token, key: (rec && rec.responseKey) || "" };
        }).catch(function () { throw "internal-error"; });
      }
      return execPromise;
    }
    if (provider !== "recaptcha" || typeof arg !== "string") {
      return Promise.reject(new Error("kiwicaptcha: execute() target is not a rendered widget id, element, or container selector"));
    }
    // v3-style execute(sitekey, {action}) on a hidden widget; the
    // sitekey stays the presented scope (the server's sitekey allowlist
    // and (sitekey, action) policy resolve it) and no score is
    // fabricated.
    var action = (opts && typeof opts.action === "string" && opts.action) || "";
    var holder = document.createElement("div");
    holder.style.display = "none";
    var inner = document.createElement("div");
    holder.appendChild(inner);
    document.body.appendChild(holder);
    var id2 = shimsRender("recaptcha", inner, { sitekey: arg, action: action || undefined });
    if (!id2) {
      if (holder.parentNode) holder.parentNode.removeChild(holder);
      return Promise.reject(new Error("kiwicaptcha: hidden render failed"));
    }
    var done = function () {
      if (core.record(id2)) core.remove(id2);
      if (holder.parentNode) holder.parentNode.removeChild(holder);
    };
    return Promise.resolve(core.execute(id2)).then(function (tok) {
      done();
      return tok;
    }, function (err) {
      done();
      throw err;
    });
  }
  function shimsSurface(provider) {
    var core = function () { return window.__kiwiCaptchaCore.core; };
    var surface = {
      render: function (target, params) { return shimsRender(provider, target, params, false); },
      execute: function (arg, opts) { return shimsExecute(provider, arg, opts); },
      reset: function (idOrEl) {
        var id = shimsResolveId(idOrEl);
        if (id) core().reset(id);
      },
      getResponse: function (idOrEl) {
        var id = shimsResolveId(idOrEl);
        return id ? core().getResponse(id) : "";
      },
      remove: function (idOrEl) {
        var id = shimsResolveId(idOrEl);
        if (!id) return;
        var entry = shimsControlById[id] || null;
        if (entry && entry.el && entry.activationHandler) {
          try { entry.el.removeEventListener("click", entry.activationHandler); } catch (e) {}
          entry.activationHandler = null;
        }
        core().remove(id);
        // The owned holder leaves with the widget; the provider control
        // itself stays where the page put it.
        if (entry && entry.holder && entry.holder.parentNode) entry.holder.parentNode.removeChild(entry.holder);
        shimsForgetControl(entry);
      },
      isExpired: function (idOrEl) {
        var id = shimsResolveId(idOrEl);
        return id ? core().isExpired(id) : false;
      },
      ready: function (fn) { shimsWhenCore(function () { core().safeCallback(fn); }); }
    };
    if (provider === "hcaptcha") {
      surface.getRespKey = function (idOrEl) {
        var id = shimsResolveId(idOrEl);
        var rec = id ? core().record(id) : null;
        return rec ? (rec.responseKey || "") : "";
      };
      surface.close = function () {};
    }
    return surface;
  }
  // Merge into a pre-seeded provider global (its own properties stay);
  // the conventional pre-loader queues drain once, in order.
  function shimsMountGlobal(name, api) {
    var existing = window[name];
    var queued = [];
    if (existing && (typeof existing === "object" || typeof existing === "function")) {
      for (var i = 0; i < SHIMS_QUEUES.length; i++) {
        var q = existing[SHIMS_QUEUES[i]];
        if (Object.prototype.toString.call(q) === "[object Array]") {
          for (var j = 0; j < q.length; j++) {
            if (typeof q[j] === "function" && queued.indexOf(q[j]) === -1) queued.push(q[j]);
          }
          try { q.length = 0; } catch (e) {}
        }
      }
      Object.assign(existing, api);
      window[name] = existing;
    } else {
      window[name] = api;
    }
    if (queued.length) {
      for (var k = 0; k < queued.length; k++) window.__kiwiCaptchaCore.core.safeCallback(queued[k]);
    }
    return window[name];
  }
  // Altcha and Friendly Captcha element conventions: existing markup
  // keeps working. Altcha: the altcha-widget element (or .altcha) with
  // a name attribute naming its response field, auto-running unless
  // data-auto="off". Friendly: .frc-captcha with data-start="auto"
  // (the default) running immediately and any other data-start value
  // deferring to the container's first activation.
  var SHIMS_SCAN_SELECTORS = ["altcha-widget", ".altcha", ".frc-captcha"];
  function shimsImplicitScan(root) {
    for (var s = 0; s < SHIMS_SCAN_SELECTORS.length; s++) {
      var selector = SHIMS_SCAN_SELECTORS[s];
      var list;
      try { list = (root || document).querySelectorAll(selector); } catch (e) { continue; }
      for (var i = 0; i < list.length; i++) {
        var el = list[i];
        if (el.nodeType !== 1 || el.getAttribute("data-kiwi-shim") === "off") continue;
        var provider = selector === ".frc-captcha" ? "friendly" : "altcha";
        shimsRender(provider, el, null, true);
      }
    }
  }
  // A deferred Friendly container starts on its first activation (the
  // incumbent focus and none start modes): one owned listener, removed
  // on the first fire.
  function shimsBindDeferred(el) {
    var fired = false;
    var handler = function () {
      if (fired) return;
      fired = true;
      el.removeEventListener("click", handler);
      el.removeEventListener("focusin", handler);
      var id = shimsResolveId(el);
      if (id) Promise.resolve(window.__kiwiCaptchaCore.core.execute(id)).catch(function () {});
    };
    el.addEventListener("click", handler);
    el.addEventListener("focusin", handler);
  }
  function shimsScanAndBind(root) {
    shimsImplicitScan(root);
    var deferred = [];
    try { deferred = (root || document).querySelectorAll('.frc-captcha[data-start]:not([data-start="auto"])'); } catch (e) {}
    for (var i = 0; i < deferred.length; i++) shimsBindDeferred(deferred[i]);
  }
  function shimsMount() {
    if (shimsMounted) return;
    shimsMounted = true;
    shimsMountGlobal("grecaptcha", shimsSurface("recaptcha"));
    shimsMountGlobal("hcaptcha", shimsSurface("hcaptcha"));
    shimsMountGlobal("turnstile", shimsSurface("turnstile"));
    shimsInjectCss();
    shimsScanAndBind(document);
    if (typeof MutationObserver !== "undefined") {
      new MutationObserver(function (mutations) {
        for (var m = 0; m < mutations.length; m++) {
          var nodes = mutations[m].addedNodes;
          for (var n = 0; n < nodes.length; n++) {
            var node = nodes[n];
            if (!node || node.nodeType !== 1) continue;
            shimsScanAndBind(node);
          }
        }
      }).observe(document.body || document.documentElement, { childList: true, subtree: true });
    }
  }
  // The driver may load after this asset (both orders are supported):
  // mount when the bridge exists, polling briefly for a late bootstrap.
  function shimsWhenCore(fn) {
    if (window.__kiwiCaptchaCore && window.__kiwiCaptchaCore.core) {
      fn();
      return;
    }
    var tries = 0;
    var timer = setInterval(function () {
      tries++;
      if (window.__kiwiCaptchaCore && window.__kiwiCaptchaCore.core) {
        clearInterval(timer);
        fn();
        return;
      }
      if (tries >= 400) clearInterval(timer);
    }, 25);
  }
  shimsWhenCore(shimsMount);
})();
