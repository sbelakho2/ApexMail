(function () {
  // ── Interaction telemetry, payload v1 (widget-telemetry.js) ─────────
  // The lazy module behind data-kiwi-telemetry: it loads ONLY when the
  // eager core (widget-driver.js) sees an enabled mode on a widget, so a
  // default page pays zero bytes for the session machinery. The factory
  // receives the RESOLVED mode from the core (the widget attribute
  // first, the container second); both enabled modes collect the same
  // aggregates below.
  //
  // Listeners attach at the FORM containing the widget, in the capture
  // phase, so interaction anywhere in the host form is observed. When
  // the widget renders without a form ancestor, the session degrades to
  // widget-only attachment (the widget element alone); that fallback is
  // a documented contract, never a silent behavior difference.
  //
  // The payload carries only coarse, privacy-preserving aggregates
  // (protocol/telemetry-v1/payload.json): event-class counts, one
  // 4-bit quantized inter-event entropy value, a focus-transition
  // count, a paste-versus-type ratio and the sample count. No raw
  // coordinates, no key values, no timing series ever leave the page:
  // each inter-event gap is reduced to a 16-bucket histogram counter
  // the moment it is measured, and only the final entropy value rides
  // the token. Collection freezes at the 32-event cap, so every count
  // is bounded by it; the cap is also the entropy rule's
  // minimum-sample count, so the rule is exactly reachable.
  var CAP = 32;

  function bucket(gapMs) {
    // min(15, floor(log2(gap + 1))): bucket 0 covers 0-1 ms, bucket 15
    // covers 32768 ms and beyond.
    var g = gapMs + 1, b = 0;
    while (b < 15 && (1 << (b + 1)) <= g) b++;
    return b;
  }

  function entropy(hist) {
    var total = 0, i;
    for (i = 0; i < 16; i++) total += hist[i];
    if (total < 2) return 0;
    var h = 0;
    for (i = 0; i < 16; i++) {
      if (hist[i] === 0) continue;
      var p = hist[i] / total;
      h -= p * Math.log(p) / Math.LN2;
    }
    var q = Math.floor(h * 15 / 4);
    return q > 15 ? 15 : (q < 0 ? 0 : q);
  }

  function session(container, W, mode) {
    if (mode !== "minimal" && mode !== "full") return { build: function () { return {}; }, stop: function () {} };
    // FORM-level attachment: the closest form of the container, then of
    // the widget; a widget without a form ancestor degrades to itself.
    var target = (container && container.closest && container.closest("form"))
      || (W && W.closest && W.closest("form")) || W;
    var counts = { fo: 0, ke: 0, pa: 0, po: 0, fm: 0 };
    var hist = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    var n = 0, ft = 0, lastT = -1, lastFocus = null;

    function onEvent(cls) {
      return function (e) {
        if (n >= CAP) return;
        n++;
        counts[cls]++;
        if (cls === "fo" && e.type === "focusin") {
          if (lastFocus !== e.target) ft++;
          lastFocus = e.target;
        }
        var now = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
        if (lastT >= 0) hist[bucket(now - lastT)]++;
        lastT = now;
      };
    }
    var onKey = function (e) { if (!e.repeat) onEvent("ke")(e); };
    var onFocusIn = function (e) { onEvent("fo")(e); };
    var onFocusOut = function (e) { onEvent("fo")(e); };
    var onPaste = onEvent("pa");
    var onPointer = onEvent("po");
    var onForm = function (e) { onEvent("fm")(e); };

    function attach() {
      // capture + passive: the listeners observe the form subtree and
      // never block or observe anything outside it.
      target.addEventListener("focusin", onFocusIn, { capture: true, passive: true });
      target.addEventListener("focusout", onFocusOut, { capture: true, passive: true });
      target.addEventListener("keydown", onKey, { capture: true, passive: true });
      target.addEventListener("paste", onPaste, { capture: true, passive: true });
      target.addEventListener("pointerdown", onPointer, { capture: true, passive: true });
      target.addEventListener("input", onForm, { capture: true, passive: true });
      target.addEventListener("change", onForm, { capture: true, passive: true });
    }
    function stop() {
      target.removeEventListener("focusin", onFocusIn, true);
      target.removeEventListener("focusout", onFocusOut, true);
      target.removeEventListener("keydown", onKey, true);
      target.removeEventListener("paste", onPaste, true);
      target.removeEventListener("pointerdown", onPointer, true);
      target.removeEventListener("input", onForm, true);
      target.removeEventListener("change", onForm, true);
    }
    function build() {
      var input = counts.ke + counts.pa;
      return {
        v: 1,
        ec: { fo: counts.fo, ke: counts.ke, pa: counts.pa, po: counts.po, fm: counts.fm },
        qe: entropy(hist),
        ft: ft,
        pt: input > 0 ? Math.floor(counts.pa * 1000 / input) : 0,
        n: n
      };
    }
    attach();
    return { build: build, stop: stop };
  }

  // The module registers itself with the internal core bridge the moment
  // it executes (the page loads it as a same-origin SRI-pinned script
  // asset only when telemetry is enabled); a module script that somehow
  // ran before the core is inert.
  var kiwiBridge = (typeof window !== "undefined" && window.__kiwiCaptchaCore) || null;
  if (kiwiBridge && typeof kiwiBridge.register === "function") {
    kiwiBridge.register("telemetry", {
      create: function (container, W, mode) { return session(container, W, mode); }
    });
  }
})();
